from threat_detection.detection.zscore import ZScoreAnomalyDetector


def _clean_features(**overrides):
    base = {
        "is_new_device": 0.0,
        "is_new_ip": 0.0,
        "is_new_active_hour": 0.0,
        "order_size_zscore": 0.0,
        "api_request_rate_zscore": 0.0,
        "cancel_delay_variance_ms": float("inf"),
    }
    base.update(overrides)
    return base


def test_normal_features_score_zero_with_no_reasons():
    detector = ZScoreAnomalyDetector()
    result = detector.score(_clean_features())
    assert result["risk_score"] == 0.0
    assert result["attack_type_guess"] is None
    assert "no feature crossed" in result["explanation"]


def test_new_device_alone_does_not_trigger_account_takeover():
    # A new device by itself is common and benign (e.g. first login from a
    # new phone) — DECISIONS.md §8 requires the SIGNALS TOGETHER.
    detector = ZScoreAnomalyDetector()
    result = detector.score(_clean_features(is_new_device=1.0))
    assert result["attack_type_guess"] is None
    assert result["risk_score"] == 0.0


def test_new_device_new_hour_and_oversized_order_triggers_account_takeover():
    detector = ZScoreAnomalyDetector()
    result = detector.score(
        _clean_features(is_new_device=1.0, is_new_active_hour=1.0, order_size_zscore=4.5)
    )
    assert result["attack_type_guess"] == "account_takeover"
    assert result["risk_score"] > 0
    assert "new device" in result["explanation"]


def test_large_order_alone_gets_a_partial_score_not_a_takeover_verdict():
    detector = ZScoreAnomalyDetector()
    result = detector.score(_clean_features(order_size_zscore=4.0))
    assert result["attack_type_guess"] is None
    assert 0 < result["risk_score"] < 100


def test_api_rate_spike_triggers_api_abuse_guess():
    detector = ZScoreAnomalyDetector()
    result = detector.score(_clean_features(api_request_rate_zscore=5.0))
    assert result["attack_type_guess"] == "api_abuse"
    assert result["risk_score"] > 0


def test_low_cancel_variance_triggers_automated_trading_guess():
    detector = ZScoreAnomalyDetector()
    result = detector.score(_clean_features(cancel_delay_variance_ms=2.0))
    assert result["attack_type_guess"] == "automated_trading"
    assert result["risk_score"] > 0


def test_high_cancel_variance_does_not_trigger_automated_trading():
    detector = ZScoreAnomalyDetector()
    result = detector.score(_clean_features(cancel_delay_variance_ms=500.0))
    assert result["attack_type_guess"] is None


def test_risk_score_never_exceeds_100():
    detector = ZScoreAnomalyDetector()
    result = detector.score(
        _clean_features(
            is_new_device=1.0,
            is_new_active_hour=1.0,
            order_size_zscore=20.0,
            api_request_rate_zscore=20.0,
            cancel_delay_variance_ms=0.0,
        )
    )
    assert result["risk_score"] <= 100.0


def test_score_result_has_expected_keys():
    detector = ZScoreAnomalyDetector()
    result = detector.score(_clean_features())
    assert set(result.keys()) == {"risk_score", "explanation", "attack_type_guess"}
