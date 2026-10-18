from datetime import datetime, timedelta, timezone

from threat_detection.detection.zscore import ZScoreAnomalyDetector
from threat_detection.features.rolling_stats import RollingStatsFeatureExtractor


def _event(event_id, timestamp, event_type, **fields):
    return {
        "event_id": event_id,
        "account_id": "ACC0001",
        "timestamp": timestamp.isoformat(),
        "event_type": event_type,
        "device_id": fields.pop("device_id", "device-home"),
        "ip_address": fields.pop("ip_address", "10.0.0.1"),
        "session_id": fields.pop("session_id", "session-1"),
        **fields,
    }


def test_takeover_signal_carries_unusual_login_context_to_the_order():
    extractor = RollingStatsFeatureExtractor()
    detector = ZScoreAnomalyDetector()
    start = datetime(2026, 9, 10, 9, 0, tzinfo=timezone.utc)

    extractor.extract(_event("login-home", start, "LOGIN", success=True))
    for index in range(10):
        extractor.extract(
            _event(
                f"normal-order-{index}",
                start + timedelta(minutes=index + 1),
                "ORDER",
                order_value=1_000.0,
            )
        )

    attack_login = _event(
        "login-new-device",
        start.replace(hour=2),
        "LOGIN",
        device_id="device-unseen",
        ip_address="185.0.0.1",
        success=True,
    )
    login_features = extractor.extract(attack_login)
    assert login_features["is_unusual_login_hour"] == 1.0

    attack_features = extractor.extract(
        _event(
            "oversized-order",
            start.replace(hour=2) + timedelta(minutes=1),
            "ORDER",
            device_id="device-unseen",
            ip_address="185.0.0.1",
            order_value=100_000.0,
        )
    )
    result = detector.score(attack_features)

    assert attack_features["account_takeover_context"] == 1.0
    assert result["attack_type_guess"] == "account_takeover"
    assert result["risk_score"] >= 50.0


def test_api_abuse_uses_the_same_client_baseline_and_clears_default_threshold():
    extractor = RollingStatsFeatureExtractor()
    detector = ZScoreAnomalyDetector()
    start = datetime(2026, 9, 10, 9, 0, tzinfo=timezone.utc)

    for index in range(3):
        extractor.extract(
            _event(
                f"normal-api-{index}",
                start + timedelta(minutes=5 * index),
                "API_REQUEST",
                client_id="client-trader",
                endpoint="/quotes",
                method="GET",
                status_code=200,
            )
        )

    result = None
    for index in range(6):
        features = extractor.extract(
            _event(
                f"burst-api-{index}",
                start + timedelta(minutes=20, seconds=index),
                "API_REQUEST",
                client_id="client-trader",
                endpoint="/quotes",
                method="GET",
                status_code=200,
            )
        )
        result = detector.score(features)

    assert features["api_request_rate_zscore"] >= 3.0
    assert result["attack_type_guess"] == "api_abuse"
    assert result["risk_score"] >= 50.0


def test_automated_trading_requires_repeated_matched_order_cancel_pairs():
    extractor = RollingStatsFeatureExtractor()
    detector = ZScoreAnomalyDetector()
    start = datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc)
    result = None

    for index in range(5):
        order_time = start + timedelta(seconds=index * 3)
        order_id = f"order-{index}"
        extractor.extract(
            _event(order_id, order_time, "ORDER", order_value=1_000.0)
        )
        features = extractor.extract(
            _event(
                f"cancel-{index}",
                order_time + timedelta(milliseconds=250),
                "CANCEL_ORDER",
                original_order_id=order_id,
                time_since_order_ms=250,
            )
        )
        result = detector.score(features)

    assert features["cancel_sequence_count"] == 5.0
    assert features["matched_cancel_delay_variance_ms"] == 0.0
    assert result["attack_type_guess"] == "automated_trading"
    assert result["risk_score"] >= 50.0


def test_unmatched_cancel_events_do_not_create_automated_trading_sequence():
    extractor = RollingStatsFeatureExtractor()
    detector = ZScoreAnomalyDetector()
    start = datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc)

    for index in range(6):
        features = extractor.extract(
            _event(
                f"orphan-cancel-{index}",
                start + timedelta(seconds=index),
                "CANCEL_ORDER",
                original_order_id=f"missing-order-{index}",
                time_since_order_ms=250,
            )
        )

    result = detector.score(features)
    assert features["cancel_sequence_count"] == 0.0
    assert result["attack_type_guess"] is None


def test_market_hours_context_uses_indian_local_time_and_weekdays():
    extractor = RollingStatsFeatureExtractor()
    monday_open = datetime(2026, 9, 14, 9, 30, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    monday_preopen = monday_open.replace(hour=9, minute=0)
    sunday_open = monday_open - timedelta(days=1)

    open_features = extractor.extract(_event("open", monday_open, "LOGIN"))
    preopen_features = extractor.extract(_event("preopen", monday_preopen, "LOGIN"))
    sunday_features = extractor.extract(_event("sunday", sunday_open, "LOGIN"))

    assert open_features["is_regular_market_hours"] == 1.0
    assert preopen_features["is_regular_market_hours"] == 0.0
    assert sunday_features["is_regular_market_hours"] == 0.0
