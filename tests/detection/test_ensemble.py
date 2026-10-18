from threat_detection.detection.ensemble import ZScoreIsolationForestEnsemble


class _Detector:
    def __init__(self, score, explanation, guess=None):
        self._score = score
        self._explanation = explanation
        self._guess = guess

    def score(self, features):
        return {
            "risk_score": self._score,
            "explanation": self._explanation,
            "attack_type_guess": self._guess,
        }


def test_ensemble_uses_max_score_and_keeps_layer_explanations():
    ensemble = ZScoreIsolationForestEnsemble(
        _Detector(50.0, "large order", "account_takeover"),
        _Detector(75.0, "outside learned envelope"),
    )

    result = ensemble.score({})

    assert result["risk_score"] == 75.0
    assert result["attack_type_guess"] == "account_takeover"
    assert result["layer_scores"] == {"zscore": 50.0, "isolation_forest": 75.0}
    assert "large order" in result["explanation"]
    assert "outside learned envelope" in result["explanation"]


def test_ensemble_preserves_zero_score_explanation_when_neither_layer_alerts():
    ensemble = ZScoreIsolationForestEnsemble(
        _Detector(0.0, "no statistical alert"),
        _Detector(0.0, "within normal envelope"),
    )

    result = ensemble.score({})

    assert result["risk_score"] == 0.0
    assert result["explanation"] == "no statistical alert"


def test_forest_alert_lists_observable_login_context_without_claiming_attribution():
    ensemble = ZScoreIsolationForestEnsemble(
        _Detector(0.0, "no statistical alert"),
        _Detector(50.0, "feature combination falls outside the learned normal envelope"),
    )

    result = ensemble.score(
        {
            "account_has_prior_history": 1.0,
            "is_new_device": 1.0,
            "is_unusual_login_hour": 1.0,
            "login_uses_mfa": 1.0,
        }
    )

    assert "context for review (not model attribution)" in result["explanation"]
    assert "device not previously seen" in result["explanation"]
    assert "successful MFA authentication reported" in result["explanation"]
