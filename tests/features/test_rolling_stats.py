from datetime import datetime, timezone

from threat_detection.features.rolling_stats import RollingStatsFeatureExtractor


def _event(**overrides):
    base = {
        "event_id": "evt-1",
        "account_id": "ACC0001",
        "timestamp": datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc).isoformat(),
        "event_type": "ORDER",
        "device_id": "device-known",
        "ip_address": "10.0.0.1",
        "session_id": "sess-1",
        "order_value": 1000.0,
    }
    base.update(overrides)
    return base


def test_first_event_for_account_is_flagged_new_device_ip_and_hour():
    extractor = RollingStatsFeatureExtractor()
    features = extractor.extract(_event())
    assert features["is_new_device"] == 1.0
    assert features["is_new_ip"] == 1.0
    assert features["is_new_active_hour"] == 1.0


def test_repeat_device_ip_hour_are_no_longer_flagged_as_new():
    extractor = RollingStatsFeatureExtractor()
    extractor.extract(_event())
    features = extractor.extract(_event(event_id="evt-2"))
    assert features["is_new_device"] == 0.0
    assert features["is_new_ip"] == 0.0
    assert features["is_new_active_hour"] == 0.0


def test_unseen_device_on_a_later_event_is_flagged():
    extractor = RollingStatsFeatureExtractor()
    extractor.extract(_event())
    features = extractor.extract(_event(event_id="evt-2", device_id="device-NEW"))
    assert features["is_new_device"] == 1.0
    # ip/hour unchanged from the first event, so still not new
    assert features["is_new_ip"] == 0.0


def test_order_size_zscore_is_zero_until_enough_history_exists():
    extractor = RollingStatsFeatureExtractor()
    # First order: no history yet to compare against.
    features = extractor.extract(_event(order_value=1000.0))
    assert features["order_size_zscore"] == 0.0


def test_order_size_zscore_flags_a_large_deviation_from_account_history():
    extractor = RollingStatsFeatureExtractor()
    # Build up a stable history of small, similar order sizes.
    for i in range(10):
        extractor.extract(_event(event_id=f"hist-{i}", order_value=100.0 + i))
    # Now a wildly larger order should produce a large positive z-score.
    features = extractor.extract(_event(event_id="spike", order_value=100_000.0))
    assert features["order_size_zscore"] > 3.0


def test_api_request_rate_zscore_flags_a_burst():
    extractor = RollingStatsFeatureExtractor()
    base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

    # Establish a low, steady baseline: a few requests, well spread out.
    for i in range(5):
        ts = base_time.replace(minute=i * 5)
        extractor.extract(
            _event(
                event_id=f"api-{i}",
                event_type="API_REQUEST",
                timestamp=ts.isoformat(),
                endpoint="/quotes",
                method="GET",
                status_code=200,
                client_id="client-1",
            )
        )

    # Then a burst: many requests within the same 60-second window.
    burst_time = base_time.replace(hour=11)
    last_features = None
    for i in range(30):
        ts = burst_time.replace(second=i)
        last_features = extractor.extract(
            _event(
                event_id=f"burst-{i}",
                event_type="API_REQUEST",
                timestamp=ts.isoformat(),
                endpoint="/quotes",
                method="GET",
                status_code=200,
                client_id="client-1",
            )
        )
    assert last_features["api_request_rate_zscore"] > 3.0


def test_cancel_delay_variance_is_low_for_near_identical_delays():
    extractor = RollingStatsFeatureExtractor()
    base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
    last_features = None
    for i in range(10):
        ts = base_time.replace(second=i)
        last_features = extractor.extract(
            _event(
                event_id=f"cancel-{i}",
                event_type="CANCEL_ORDER",
                timestamp=ts.isoformat(),
                original_order_id="order-x",
                time_since_order_ms=250 + (i % 2),  # 250 or 251ms — near-zero variance
            )
        )
    assert last_features["cancel_delay_variance_ms"] < 5.0


def test_cancel_delay_variance_is_high_for_human_like_delays():
    extractor = RollingStatsFeatureExtractor()
    base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
    human_delays = [800, 3200, 1500, 9000, 400, 5200, 1100, 7300, 2200, 600]
    last_features = None
    for i, delay in enumerate(human_delays):
        ts = base_time.replace(second=i)
        last_features = extractor.extract(
            _event(
                event_id=f"cancel-{i}",
                event_type="CANCEL_ORDER",
                timestamp=ts.isoformat(),
                original_order_id="order-x",
                time_since_order_ms=delay,
            )
        )
    assert last_features["cancel_delay_variance_ms"] > 100.0


def test_extractor_keeps_separate_state_per_account():
    extractor = RollingStatsFeatureExtractor()
    extractor.extract(_event(account_id="ACC0001", device_id="device-A"))
    # A different account's first event should also be "new", independent
    # of what ACC0001 has already seen.
    features = extractor.extract(_event(account_id="ACC0002", event_id="evt-2", device_id="device-A"))
    assert features["is_new_device"] == 1.0
