import pytest

from threat_detection.api.event_store import SQLiteEventStore


def _record(event_id, account_id="ACC1", score=10.0):
    return {
        "event_id": event_id,
        "account_id": account_id,
        "risk_score": score,
        "explanation": "example reason",
    }


def test_event_history_survives_store_reopen(tmp_path):
    database_path = tmp_path / "history.sqlite3"
    first_store = SQLiteEventStore(database_path)
    first_store.append(_record("evt-1"))
    first_store.close()

    reopened_store = SQLiteEventStore(database_path)
    try:
        assert reopened_store.recent(10) == [_record("evt-1")]
    finally:
        reopened_store.close()


def test_event_store_is_bounded_and_refreshes_duplicate_event():
    store = SQLiteEventStore(":memory:", max_events=2)
    try:
        store.append(_record("evt-1"))
        store.append(_record("evt-2"))
        store.append(_record("evt-3"))
        store.append(_record("evt-2", score=55.0))

        assert store.recent(10) == [
            _record("evt-3"),
            _record("evt-2", score=55.0),
        ]
    finally:
        store.close()


def test_event_store_requires_a_positive_retention_limit():
    with pytest.raises(ValueError, match="at least 1"):
        SQLiteEventStore(":memory:", max_events=0)
