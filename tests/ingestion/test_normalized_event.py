import pytest
from pydantic import ValidationError

from threat_detection.ingestion.base import BrokerEventAdapter
from threat_detection.ingestion.schema import NormalizedEvent


def _valid_order_event():
    return {
        "event_id": "evt-1",
        "account_id": "ACC1",
        "timestamp": "2026-09-18T10:15:00+00:00",
        "event_type": "ORDER",
        "session_id": "session-1",
        "symbol": "TCS",
        "order_type": "buy",
        "quantity": 10,
        "price": 100.0,
        "order_value": 1000.0,
    }


def test_canonical_event_accepts_a_valid_normalized_order():
    event = NormalizedEvent.model_validate(_valid_order_event())

    assert event.event_type == "ORDER"
    assert event.order_value == event.quantity * event.price


@pytest.mark.parametrize("label", ["is_attack", "attack_type"])
def test_canonical_event_rejects_synthetic_ground_truth(label):
    payload = {**_valid_order_event(), label: True}

    with pytest.raises(ValidationError, match="ground-truth"):
        NormalizedEvent.model_validate(payload)


def test_canonical_event_rejects_broker_fields_until_an_adapter_maps_them():
    payload = {**_valid_order_event(), "broker_order_status": "FILLED"}

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        NormalizedEvent.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timestamp", "2026-09-18T10:15:00"),
        ("quantity", 0),
        ("price", float("inf")),
        ("order_value", -1.0),
        ("time_since_order_ms", -1.0),
        ("status_code", 700),
    ],
)
def test_canonical_event_rejects_invalid_timestamps_and_numeric_values(field, value):
    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate({**_valid_order_event(), field: value})


def test_broker_event_adapter_is_an_explicit_extension_contract():
    assert BrokerEventAdapter.__abstractmethods__ == frozenset({"normalize"})
