"""Unsupervised Isolation Forest comparison detector.

Fit this detector on a separate, unlabeled normal-history stream before use.
The estimator sees only finite numeric feature values; it never sees events or
ground-truth labels. Its output is a coarse anomaly alert, not an attack-type
classification or a calibrated probability.
"""

from __future__ import annotations

import math
from typing import Any, Iterable

from sklearn.ensemble import IsolationForest

from threat_detection.detection.base import AnomalyDetector

_FEATURE_NAMES = (
    "event_type_is_login",
    "event_type_is_order",
    "event_type_is_cancel_order",
    "event_type_is_api_request",
    "event_type_is_device_change",
    "event_type_is_logout",
    "login_uses_password",
    "login_uses_token",
    "login_uses_mfa",
    "account_has_prior_history",
    "is_new_device",
    "is_new_ip",
    "is_new_active_hour",
    "is_unusual_login_hour",
    "account_takeover_context",
    "is_regular_market_hours",
    "order_size_zscore",
    "order_value_zscore",
    "api_request_rate_zscore",
    "cancel_sequence_count",
    "matched_cancel_delay_variance_ms",
)


class IsolationForestAnomalyDetector(AnomalyDetector):
    """A fitted Isolation Forest adapted to the existing single-event contract."""

    def __init__(self, *, random_state: int = 42, n_estimators: int = 200) -> None:
        self._model = IsolationForest(
            contamination="auto", random_state=random_state,
            n_estimators=n_estimators, n_jobs=1,
        )
        self._is_fitted = False
        self._decision_cutoff = 0.0

    @staticmethod
    def _vector(features: dict[str, float]) -> list[float]:
        values: list[float] = []
        for name in _FEATURE_NAMES:
            value = float(features.get(name, 0.0))
            if name == "matched_cancel_delay_variance_ms":
                # Infinity means the variance is not yet measurable. Represent
                # applicability separately so sklearn receives finite values.
                values.append(1.0 if math.isfinite(value) else 0.0)
                value = math.log1p(min(max(value, 0.0), 1e12)) if math.isfinite(value) else 0.0
            elif not math.isfinite(value):
                value = 0.0
            values.append(max(-20.0, min(20.0, value)))
        return values

    def fit(self, normal_feature_vectors: Iterable[dict[str, float]]) -> None:
        """Fit only on features from a separately prepared normal-only stream."""
        vectors = [self._vector(features) for features in normal_feature_vectors]
        if len(vectors) < 2:
            raise ValueError("Isolation Forest requires at least two normal feature vectors")
        self._model.fit(vectors)
        self._is_fitted = True

    def calibrate(
        self,
        normal_feature_vectors: Iterable[dict[str, float]],
        *,
        target_false_positive_rate: float = 0.05,
    ) -> None:
        """Choose an alert cutoff from a separate normal-only calibration set."""
        if not self._is_fitted:
            raise RuntimeError("fit the Isolation Forest before calibrating it")
        if not 0.0 < target_false_positive_rate < 0.5:
            raise ValueError("target_false_positive_rate must be between 0 and 0.5")
        vectors = [self._vector(features) for features in normal_feature_vectors]
        if not vectors:
            raise ValueError("calibration requires at least one normal feature vector")
        decisions = sorted(float(value) for value in self._model.decision_function(vectors))
        # Nearest-rank quantile: alert below the selected normal-score cutoff.
        rank = max(0, math.ceil(target_false_positive_rate * len(decisions)) - 1)
        self._decision_cutoff = decisions[rank]

    def score(self, features: dict[str, float]) -> dict[str, Any]:
        if not self._is_fitted:
            raise RuntimeError("fit the Isolation Forest on normal history before scoring")
        vector = [self._vector(features)]
        decision_value = float(self._model.decision_function(vector)[0])
        is_outlier = decision_value < self._decision_cutoff
        # The forest produces a binary outlier decision, not calibrated
        # severity. An outlier reaches the minimum review threshold but does
        # not by itself imply a high-risk event.
        risk_score = 50.0 if is_outlier else 0.0
        return {
            "risk_score": risk_score,
            "explanation": (
                "feature combination falls outside the learned normal envelope"
                if is_outlier else "feature combination is within the learned normal envelope"
            ),
            "attack_type_guess": None,
            "model_decision_value": decision_value,
        }
