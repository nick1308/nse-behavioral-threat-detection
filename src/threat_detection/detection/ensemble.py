"""Combine the interpretable score and an unsupervised comparison score."""

from __future__ import annotations

from typing import Any

from threat_detection.detection.base import AnomalyDetector


class ZScoreIsolationForestEnsemble(AnomalyDetector):
    """Use the strongest layer score while preserving both explanations."""

    def __init__(
        self,
        zscore_detector: AnomalyDetector,
        isolation_forest_detector: AnomalyDetector,
    ) -> None:
        self._zscore_detector = zscore_detector
        self._isolation_forest_detector = isolation_forest_detector

    def score(self, features: dict[str, float]) -> dict[str, Any]:
        zscore_result = self._zscore_detector.score(features)
        if float(features.get("account_has_prior_history", 1.0)) < 1.0:
            forest_result = {
                "risk_score": 0.0,
                "explanation": "Isolation Forest held during account cold start",
                "attack_type_guess": None,
            }
        else:
            forest_result = self._isolation_forest_detector.score(features)
        zscore_score = float(zscore_result["risk_score"])
        forest_score = float(forest_result["risk_score"])
        selected = zscore_result if zscore_score >= forest_score else forest_result
        explanations = []
        if zscore_score > 0.0:
            explanations.append(f"z-score: {zscore_result['explanation']}")
        if forest_score > 0.0:
            explanations.append(f"Isolation Forest: {forest_result['explanation']}")
        explanation = "; ".join(explanations) or str(selected.get("explanation", "no alert"))
        return {
            "risk_score": max(zscore_score, forest_score),
            "explanation": explanation,
            "attack_type_guess": zscore_result.get("attack_type_guess"),
            "layer_scores": {"zscore": zscore_score, "isolation_forest": forest_score},
        }
