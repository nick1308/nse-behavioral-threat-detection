import os

import pytest

from threat_detection.api.event_store import SQLiteEventStore


def pytest_configure(config):
    # Keep test collection from reading or creating developer-local databases/maps.
    os.environ["THREAT_DETECTION_DB_PATH"] = ":memory:"
    os.environ["THREAT_DETECTION_FIELD_MAP"] = ""
    os.environ["THREAT_DETECTION_EVENT_TYPE_MAP"] = ""


@pytest.fixture(autouse=True)
def isolate_api_event_history(monkeypatch):
    """Keep API test history isolated from the developer's local SQLite file."""
    from threat_detection.api import main

    event_store = SQLiteEventStore(":memory:")
    monkeypatch.setattr(main, "_event_store", event_store)
    monkeypatch.setattr(main, "_broker_event_adapter", None)
    yield
    event_store.close()
