from threat_detection.ingestion.base import EventSource


def test_event_source_is_abstract():
    assert EventSource.__abstractmethods__ == frozenset({"events"})
