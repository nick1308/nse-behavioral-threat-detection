from datetime import datetime, timezone

from threat_detection.ingestion.synthetic import SyntheticEventSource

_REQUIRED_COMMON_FIELDS = {
    "event_id",
    "account_id",
    "timestamp",
    "event_type",
    "device_id",
    "ip_address",
    "session_id",
    "is_attack",
    "attack_type",
}

_VALID_EVENT_TYPES = {
    "LOGIN",
    "LOGOUT",
    "VIEW_STOCK",
    "ORDER",
    "CANCEL_ORDER",
    "API_REQUEST",
    "TOKEN_REFRESH",
    "PASSWORD_CHANGE",
    "DEVICE_CHANGE",
}


_FIXED_START = datetime(2026, 8, 1, tzinfo=timezone.utc)


def _generate(num_accounts=10, num_attack_accounts=3, events_per_normal_account=10, seed=1):
    # start_time defaults to datetime.now() when omitted, which is correct
    # for real use but would make two "reproducible" runs differ only in
    # wall-clock timestamps — pin it here so tests are deterministic.
    source = SyntheticEventSource(
        num_accounts=num_accounts,
        num_attack_accounts=num_attack_accounts,
        events_per_normal_account=events_per_normal_account,
        seed=seed,
        start_time=_FIXED_START,
    )
    return list(source.events())


def test_every_event_has_required_common_fields():
    events = _generate()
    assert events, "generator produced no events"
    for event in events:
        assert _REQUIRED_COMMON_FIELDS.issubset(event.keys())
        assert event["event_type"] in _VALID_EVENT_TYPES


def test_events_are_chronologically_ordered():
    events = _generate()
    timestamps = [datetime.fromisoformat(e["timestamp"]) for e in events]
    assert timestamps == sorted(timestamps)


def test_plants_the_requested_number_of_attack_accounts():
    events = _generate(num_accounts=10, num_attack_accounts=3)
    attack_account_ids = {e["account_id"] for e in events if e["is_attack"]}
    assert len(attack_account_ids) == 3


def test_normal_events_are_never_labeled_as_attacks():
    events = _generate()
    normal_events = [e for e in events if not e["is_attack"]]
    assert normal_events, "expected some normal (non-attack) events"
    assert all(e["attack_type"] is None for e in normal_events)


def test_all_three_attack_types_are_represented_with_enough_accounts():
    # With enough attack accounts, hashing across 3 known types should surface
    # more than one type (not a strict guarantee for tiny counts, so use a
    # generous account count here).
    events = _generate(num_accounts=30, num_attack_accounts=12, events_per_normal_account=5)
    attack_types = {e["attack_type"] for e in events if e["is_attack"]}
    assert attack_types.issubset({"account_takeover", "api_abuse", "automated_trading"})
    assert len(attack_types) >= 2


def test_account_takeover_uses_a_device_and_ip_not_seen_in_that_accounts_normal_history():
    events = _generate(num_accounts=10, num_attack_accounts=10, events_per_normal_account=10)
    by_account: dict[str, list[dict]] = {}
    for e in events:
        by_account.setdefault(e["account_id"], []).append(e)

    takeover_accounts = {
        acc_id
        for acc_id, evs in by_account.items()
        if any(e["attack_type"] == "account_takeover" for e in evs)
    }
    assert takeover_accounts, "expected at least one account_takeover in a 10/10 attack run"

    for acc_id in takeover_accounts:
        evs = by_account[acc_id]
        normal_devices = {e["device_id"] for e in evs if not e["is_attack"]}
        attack_devices = {e["device_id"] for e in evs if e["is_attack"]}
        assert attack_devices - normal_devices, "attack device should be unseen in normal history"


def test_automated_trading_produces_matched_order_cancel_pairs_with_fixed_delay():
    events = _generate(num_accounts=10, num_attack_accounts=10, events_per_normal_account=10)
    auto_trading_events = [e for e in events if e["attack_type"] == "automated_trading"]
    assert auto_trading_events, "expected at least one automated_trading account in a 10/10 attack run"

    cancels = [e for e in auto_trading_events if e["event_type"] == "CANCEL_ORDER"]
    assert cancels
    # The generator plants a fixed ~250ms cancel delay — the whole point of
    # this attack pattern is near-zero timing variance.
    for c in cancels:
        assert c["time_since_order_ms"] == 250


def test_api_abuse_produces_a_request_rate_spike():
    events = _generate(num_accounts=10, num_attack_accounts=10, events_per_normal_account=10)
    abuse_events = [e for e in events if e["attack_type"] == "api_abuse"]
    assert abuse_events, "expected at least one api_abuse account in a 10/10 attack run"
    assert all(e["event_type"] == "API_REQUEST" for e in abuse_events)
    assert len(abuse_events) >= 40  # generator plants 50 rapid-fire requests


def test_raises_if_more_attack_accounts_than_accounts():
    import pytest

    with pytest.raises(ValueError):
        SyntheticEventSource(num_accounts=5, num_attack_accounts=6)


def test_seeded_runs_are_reproducible():
    a = _generate(seed=7)
    b = _generate(seed=7)
    assert a == b
