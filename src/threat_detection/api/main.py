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

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, ValidationError

from threat_detection.api.event_store import SQLiteEventStore
from threat_detection.detection.ensemble import ZScoreIsolationForestEnsemble
from threat_detection.detection.zscore import ZScoreAnomalyDetector
from threat_detection.evaluation.harness import fit_isolation_forest
from threat_detection.features.rolling_stats import RollingStatsFeatureExtractor
from threat_detection.ingestion.base import ConfiguredFieldMapAdapter
from threat_detection.ingestion.schema import NormalizedEvent as EventIn
from threat_detection.ingestion.synthetic import SyntheticEventSource

app = FastAPI(title="NSE Behavioral Threat Detection", version="0.1.0")
_STATIC_DIR = Path(__file__).with_name("static")

# Single shared scoring instances for the process lifetime — see module docstring.
# Scored history persists locally; rolling feature state remains process-local.
_feature_extractor = RollingStatsFeatureExtractor()
_MAX_RECENT_EVENTS = 500
_event_store = SQLiteEventStore(
    os.environ.get("THREAT_DETECTION_DB_PATH", "data/events.sqlite3"),
    max_events=_MAX_RECENT_EVENTS,
)


def _read_mapping_setting(setting_name: str) -> dict[str, str]:
    raw_setting = os.environ.get(setting_name)
    if raw_setting is None or not raw_setting.strip():
        return {}
    try:
        parsed_setting = json.loads(raw_setting)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{setting_name} must contain a JSON object") from error
    if not isinstance(parsed_setting, dict):
        raise RuntimeError(f"{setting_name} must contain a JSON object")
    if any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in parsed_setting.items()
    ):
        raise RuntimeError(f"{setting_name} must map strings to strings")
    return parsed_setting


def _build_source_adapter() -> ConfiguredFieldMapAdapter | None:
    field_map = _read_mapping_setting("THREAT_DETECTION_FIELD_MAP")
    event_type_map = _read_mapping_setting("THREAT_DETECTION_EVENT_TYPE_MAP")
    if not field_map and not event_type_map:
        return None
    return ConfiguredFieldMapAdapter(
        field_map=field_map,
        event_type_map=event_type_map,
    )


_broker_event_adapter = _build_source_adapter()


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
    return {"events": _event_store.recent(limit)}


def _score_and_record(
    event: EventIn,
    *,
    feature_extractor: RollingStatsFeatureExtractor | None = None,
) -> dict[str, Any]:
    event_dict = event.model_dump(exclude_none=True)
    extractor = feature_extractor or _feature_extractor
    result = _detector.score(extractor.extract(event_dict))
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
    _event_store.append(record)
    return result


@app.post("/demo/replay")
def replay_demo(seed: int = Query(default=42, ge=0)) -> dict[str, int]:
    """Replay a reproducible synthetic stream through the real scoring path.

    Ground-truth labels are removed before request validation and scoring, and
    are never returned to the browser.
    """
    replay_feature_extractor = RollingStatsFeatureExtractor()
    source = SyntheticEventSource(
        num_accounts=8,
        num_attack_accounts=3,
        events_per_normal_account=20,
        seed=seed,
        start_time=datetime(2026, 9, 18, tzinfo=timezone.utc),
    )
    processed = 0
    alert_count = 0
    for generated_event in source.events():
        detector_input = {
            key: value
            for key, value in generated_event.items()
            if key not in {"is_attack", "attack_type"}
        }
        result = _score_and_record(
            EventIn.model_validate(detector_input),
            feature_extractor=replay_feature_extractor,
        )
        processed += 1
        alert_count += int(result["risk_score"] >= 50)
    return {
        "processed_events": processed,
        "alert_count": alert_count,
    }


@app.post("/score", response_model=ScoreOut)
def score_event(event: EventIn) -> dict[str, Any]:
    """Run one event through features and ensemble scoring."""
    return _score_and_record(event)


@app.post("/score/source", response_model=ScoreOut)
def score_source_event(source_event: dict[str, Any] = Body(...)) -> dict[str, Any]:
    """Map a configured flat broker record, then score its normalized event.

    This endpoint does not connect to a broker or authenticate callers. It is
    disabled unless a deployment configures its source-field mapping at start.
    """
    if _broker_event_adapter is None:
        raise HTTPException(
            status_code=503,
            detail="No source field mapping is configured for this endpoint.",
        )
    try:
        normalized_event = _broker_event_adapter.normalize(source_event)
    except ValidationError as error:
        safe_errors = [
            {
                "loc": list(item["loc"]),
                "msg": item["msg"],
                "type": item["type"],
            }
            for item in error.errors()
        ]
        raise HTTPException(status_code=422, detail=safe_errors) from error
    return _score_and_record(normalized_event)
