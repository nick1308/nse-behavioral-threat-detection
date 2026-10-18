import os

import pytest

# Avoid creating or touching the developer's default database during tests.
os.environ["THREAT_DETECTION_DB_PATH"] = ":memory:"

from threat_detection.api import main
from threat_detection.api.event_store import SQLiteEventStore


@pytest.fixture(autouse=True)
def isolate_api_event_history(monkeypatch):
    """Keep API test history isolated from the developer's local SQLite file."""
    event_store = SQLiteEventStore(":memory:")
    monkeypatch.setattr(main, "_event_store", event_store)
    yield
    event_store.close()
