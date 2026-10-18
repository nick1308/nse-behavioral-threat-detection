import pytest

from threat_detection.detection.isolation_forest import IsolationForestAnomalyDetector


def test_isolation_forest_requires_normal_training_data_before_scoring():
    detector = IsolationForestAnomalyDetector(n_estimators=10)
    with pytest.raises(RuntimeError, match="fit"):
        detector.score({})


def test_isolation_forest_fits_finite_vectors_and_returns_existing_score_shape():
    detector = IsolationForestAnomalyDetector(n_estimators=20)
    detector.fit([
        {"order_size_zscore": 0.0, "matched_cancel_delay_variance_ms": float("inf")},
        {"order_size_zscore": 0.2, "matched_cancel_delay_variance_ms": 100.0},
        {"order_size_zscore": -0.1, "matched_cancel_delay_variance_ms": 120.0},
    ])

    result = detector.score({"order_size_zscore": 12.0, "matched_cancel_delay_variance_ms": 0.0})

    assert 0.0 <= result["risk_score"] <= 100.0
    assert isinstance(result["explanation"], str)
    assert result["attack_type_guess"] is None
    assert "model_decision_value" in result


def test_isolation_forest_calibrates_cutoff_from_a_separate_normal_sample():
    detector = IsolationForestAnomalyDetector(n_estimators=20)
    normal = [
        {"api_request_rate_zscore": float(index % 3), "is_regular_market_hours": 1.0}
        for index in range(40)
    ]
    detector.fit(normal)
    detector.calibrate(normal, target_false_positive_rate=0.1)
    result = detector.score({"api_request_rate_zscore": 20.0, "is_regular_market_hours": 0.0})

    assert result["risk_score"] in {0.0, 50.0}


def test_binary_forest_outlier_maps_only_to_minimum_review_score(monkeypatch):
    detector = IsolationForestAnomalyDetector(n_estimators=10)
    detector._is_fitted = True
    monkeypatch.setattr(detector._model, "decision_function", lambda vectors: [-1.0])

    result = detector.score({})

    assert result["risk_score"] == 50.0
    assert "outside the learned normal envelope" in result["explanation"]


def test_isolation_forest_rejects_invalid_calibration_rate():
    detector = IsolationForestAnomalyDetector(n_estimators=10)
    detector.fit([{"value": 0.0}, {"value": 1.0}])
    with pytest.raises(ValueError, match="target_false_positive_rate"):
        detector.calibrate([{"value": 0.0}], target_false_positive_rate=0.5)
