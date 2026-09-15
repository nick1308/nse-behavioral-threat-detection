"""FastAPI application entry point.

Wires the full Review-2 pipeline end to end: an incoming event is run
through the statistical FeatureExtractor, then the ZScoreAnomalyDetector,
and the resulting risk score + explanation is returned as JSON
(DESIGN.md §2, step 4: "POST /score ... returns
{risk_score, explanation, attack_type_guess} as JSON").

The FeatureExtractor is instantiated once at module import and reused
across requests (not per-request), because its whole purpose is to
maintain rolling per-account state — a fresh extractor every request
would have no history to compare against and every event would look
"new" forever.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

from threat_detection.detection.zscore import ZScoreAnomalyDetector
from threat_detection.features.rolling_stats import RollingStatsFeatureExtractor

app = FastAPI(title="NSE Behavioral Threat Detection", version="0.1.0")

# Single shared instances for the process lifetime — see module docstring.
# Review-2 scope is a single-process prototype (DESIGN.md §3: Redis/DB
# persistence is future work), so in-memory state here is intentional,
# not a shortcut we forgot to fix.
_feature_extractor = RollingStatsFeatureExtractor()
_detector = ZScoreAnomalyDetector()


class EventIn(BaseModel):
    """Request body for POST /score — mirrors EVENT_SCHEMA.md's common
    fields plus the handful of type-specific fields our current features
    actually use (order_value, time_since_order_ms). Ground-truth fields
    (is_attack, attack_type) are deliberately NOT accepted here: this
    endpoint scores events the way a real deployment would receive them,
    without a "cheat" label attached (see synthetic.py's module docstring
    for why the detection pipeline must never see ground truth).
    """

    event_id: str
    account_id: str
    timestamp: str
    event_type: str
    device_id: str
    ip_address: str
    session_id: str
    order_value: Optional[float] = None
    time_since_order_ms: Optional[float] = None

    model_config = {
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


class ScoreOut(BaseModel):
    risk_score: float = Field(..., description="0-100 explainable risk score")
    explanation: str
    attack_type_guess: Optional[str] = None


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness check used by Docker/orchestration and by tests."""
    return {"status": "ok"}


@app.post("/score", response_model=ScoreOut)
def score_event(event: EventIn) -> dict[str, Any]:
    """Run one event through the pipeline: features -> detection -> risk score.

    This is the Review-2 feasibility demo endpoint (DESIGN.md §2, step 4):
    it proves the whole vertical slice — ingestion-shaped input, rolling
    per-account features, z-score detection, explainable output — works
    end to end, not just as isolated unit-tested layers.
    """
    event_dict = event.model_dump(exclude_none=True)
    features = _feature_extractor.extract(event_dict)
    result = _detector.score(features)
    return result
