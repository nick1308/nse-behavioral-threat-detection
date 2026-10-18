"""Combine the interpretable score and an unsupervised comparison score."""

from __future__ import annotations

from typing import Any

from threat_detection.detection.base import AnomalyDetector


class ZScoreIsolationForestEnsemble(AnomalyDetector):
    """Use the strongest layer score while preserving both explanations."""

    @staticmethod
    def _forest_context(features: dict[str, float]) -> str:
        """Return observable facts for review without claiming model attribution."""
        context: list[str] = []
        if features.get("is_new_device", 0.0) >= 1.0:
            context.append("device not previously seen for this account")
        if features.get("is_unusual_login_hour", 0.0) >= 1.0:
            context.append("login at an hour not previously observed for this account")
        if features.get("login_uses_mfa", 0.0) >= 1.0:
            context.append("successful MFA authentication reported")
        elif features.get("login_uses_password", 0.0) >= 1.0:
            context.append("successful password authentication reported")
        elif features.get("login_uses_token", 0.0) >= 1.0:
            context.append("successful token authentication reported")
        if features.get("recent_login_mfa_verified", 0.0) >= 1.0:
            context.append("MFA success reported for the same recent session")
        if not context:
            return ""
        return "; context for review (not model attribution): " + "; ".join(context)

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
            explanations.append(
                f"Isolation Forest: {forest_result['explanation']}"
                f"{self._forest_context(features)}"
            )
        explanation = "; ".join(explanations) or str(selected.get("explanation", "no alert"))
        return {
            "risk_score": max(zscore_score, forest_score),
            "explanation": explanation,
            "attack_type_guess": zscore_result.get("attack_type_guess"),
            "layer_scores": {"zscore": zscore_score, "isolation_forest": forest_score},
        }
