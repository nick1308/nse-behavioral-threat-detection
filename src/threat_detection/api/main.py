"""FastAPI entry point for the synthetic behavioral scoring prototype.

An incoming event passes through the shared rolling feature extractor and the
z-score/Isolation Forest max-score ensemble. `/score` returns the combined
risk score, component scores, explanation, and z-score pattern guess.

The FeatureExtractor is instantiated once at module import and reused
across requests (not per-request), because its whole purpose is to
maintain rolling per-account state — a fresh extractor every request
would have no history to compare against and every event would look
"new" forever.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Optional

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator, model_validator

from threat_detection.detection.ensemble import ZScoreIsolationForestEnsemble
from threat_detection.detection.zscore import ZScoreAnomalyDetector
from threat_detection.evaluation.harness import fit_isolation_forest
from threat_detection.features.rolling_stats import RollingStatsFeatureExtractor
from threat_detection.ingestion.synthetic import SyntheticEventSource

app = FastAPI(title="NSE Behavioral Threat Detection", version="0.1.0")
_STATIC_DIR = Path(__file__).with_name("static")

# Single shared instances for the process lifetime — see module docstring.
# This prototype is single-process and state is not persisted across restarts.
_feature_extractor = RollingStatsFeatureExtractor()
_recent_events: list[dict[str, Any]] = []
_MAX_RECENT_EVENTS = 500


def _build_detector() -> ZScoreIsolationForestEnsemble:
    """Build the demo model from reproducible normal-only synthetic history."""
    start_time = datetime(2026, 9, 18, tzinfo=timezone.utc)
    forest, _ = fit_isolation_forest(
        SyntheticEventSource(
            num_accounts=20,
            num_attack_accounts=0,
            seed=7,
            start_time=start_time,
        ),
        calibration_event_source=SyntheticEventSource(
            num_accounts=20,
            num_attack_accounts=0,
            seed=8,
            start_time=start_time,
        ),
        target_false_positive_rate=0.05,
    )
    return ZScoreIsolationForestEnsemble(ZScoreAnomalyDetector(), forest)


_detector = _build_detector()


class EventIn(BaseModel):
    """Normalized broker-event payload accepted by the scoring API.

    Broker-specific adapters should map their authorized telemetry into this
    contract. Ground-truth fields are explicitly rejected; unknown fields are
    rejected rather than silently discarded.
    """

    event_id: str
    account_id: str
    timestamp: str
    event_type: Literal[
        "LOGIN", "LOGOUT", "VIEW_STOCK", "ORDER", "CANCEL_ORDER",
        "API_REQUEST", "TOKEN_REFRESH", "PASSWORD_CHANGE", "DEVICE_CHANGE",
    ]
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    session_id: str
    success: Optional[bool] = None
    auth_method: Optional[Literal["password", "token", "mfa"]] = None
    symbol: Optional[str] = None
    order_type: Optional[Literal["buy", "sell"]] = None
    quantity: Optional[int] = None
    price: Optional[float] = None
    order_value: Optional[float] = None
    time_since_order_ms: Optional[float] = None
    client_id: Optional[str] = None
    original_order_id: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[Literal["GET", "POST", "PUT", "DELETE"]] = None
    status_code: Optional[int] = None
    token_type: Optional[Literal["access", "refresh"]] = None
    initiated_by: Optional[Literal["user", "admin_reset"]] = None
    previous_device_id: Optional[str] = None
    new_device_id: Optional[str] = None

    model_config = {
        "extra": "forbid",
        "json_schema_extra": {
            "example": {
                "event_id": "evt-demo-1",
                "account_id": "ACC0001",
                "timestamp": "2026-09-18T10:15:00+00:00",
                "event_type": "ORDER",
                "device_id": "device-abc123",
                "ip_address": "10.0.0.5",
                "session_id": "sess-1",
                "order_value": 50000.0,
            }
        }
    }

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_iso8601(cls, value: str) -> str:
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("timestamp must be an ISO 8601 datetime") from error
        return value

    @model_validator(mode="before")
    @classmethod
    def reject_ground_truth(cls, value: Any) -> Any:
        if isinstance(value, dict) and {"is_attack", "attack_type"}.intersection(value):
            raise ValueError("ground-truth fields are not accepted by the scoring API")
        return value


class ScoreOut(BaseModel):
    risk_score: float = Field(..., description="0-100 explainable risk score")
    explanation: str
    attack_type_guess: Optional[str] = None
    layer_scores: dict[str, float]


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness check used by Docker/orchestration and by tests."""
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    """Serve the analyst dashboard from the same local FastAPI application."""
    return FileResponse(_STATIC_DIR / "index.html")


@app.get("/dashboard.js", include_in_schema=False)
def dashboard_script() -> FileResponse:
    return FileResponse(_STATIC_DIR / "dashboard.js", media_type="text/javascript")


@app.get("/dashboard.css", include_in_schema=False)
def dashboard_styles() -> FileResponse:
    return FileResponse(_STATIC_DIR / "dashboard.css", media_type="text/css")


@app.get("/events")
def recent_events(limit: int = Query(default=100, ge=1, le=_MAX_RECENT_EVENTS)) -> dict[str, Any]:
    """Return recent scored event summaries for the analyst UI."""
    return {"events": list(reversed(_recent_events[-limit:]))}


def _score_and_record(event: EventIn) -> dict[str, Any]:
    event_dict = event.model_dump(exclude_none=True)
    result = _detector.score(_feature_extractor.extract(event_dict))
    record = {
        "event_id": event.event_id,
        "account_id": event.account_id,
        "timestamp": event.timestamp,
        "event_type": event.event_type,
        "risk_score": result["risk_score"],
        "explanation": result["explanation"],
        "attack_type_guess": result["attack_type_guess"],
        "layer_scores": result["layer_scores"],
    }
    _recent_events.append(record)
    del _recent_events[:-_MAX_RECENT_EVENTS]
    return result


@app.post("/demo/replay")
def replay_demo(seed: int = Query(default=42, ge=0)) -> dict[str, int]:
    """Replay a reproducible synthetic stream through the real scoring path.

    Ground-truth labels are removed before request validation and scoring, and
    are never returned to the browser.
    """
    global _feature_extractor
    _feature_extractor = RollingStatsFeatureExtractor()
    _recent_events.clear()
    source = SyntheticEventSource(
        num_accounts=8,
        num_attack_accounts=3,
        events_per_normal_account=20,
        seed=seed,
    )
    processed = 0
    for generated_event in source.events():
        detector_input = {
            key: value
            for key, value in generated_event.items()
            if key not in {"is_attack", "attack_type"}
        }
        _score_and_record(EventIn.model_validate(detector_input))
        processed += 1
    return {
        "processed_events": processed,
        "alert_count": sum(item["risk_score"] >= 50 for item in _recent_events),
    }


@app.post("/score", response_model=ScoreOut)
def score_event(event: EventIn) -> dict[str, Any]:
    """Run one event through features and ensemble scoring."""
    return _score_and_record(event)
