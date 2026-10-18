"""Interfaces for the event ingestion layer."""

from abc import ABC, abstractmethod
from typing import Any, Iterator, Mapping

from threat_detection.ingestion.schema import NormalizedEvent


class BrokerEventAdapter(ABC):
    """Maps one source-specific broker record to the canonical event model.

    Implementations belong to a deployment that has authorization to consume
    that broker's event feed. Source authentication and transport are outside
    this mapping contract.
    """

    @abstractmethod
    def normalize(self, broker_event: Mapping[str, Any]) -> NormalizedEvent:
        """Validate and translate a broker record into a normalized event."""
        raise NotImplementedError


class ConfiguredFieldMapAdapter(BrokerEventAdapter):
    """Normalize flat source records using configured field and type maps.

    ``field_map`` maps canonical field names to source field names. Fields not
    listed use their canonical name, which makes partial mappings concise.
    Unknown source fields are ignored; required canonical fields and values are
    still checked by ``NormalizedEvent``. For nested or value-transforming
    broker payloads, implement ``BrokerEventAdapter`` directly.
    """

    def __init__(
        self,
        *,
        field_map: Mapping[str, str] | None = None,
        event_type_map: Mapping[str, str] | None = None,
    ) -> None:
        valid_fields = set(NormalizedEvent.model_fields)
        unknown_fields = set(field_map or {}).difference(valid_fields)
        if unknown_fields:
            raise ValueError(f"field_map targets unknown canonical fields: {sorted(unknown_fields)}")
        self._field_map = dict(field_map or {})
        self._event_type_map = dict(event_type_map or {})

    def normalize(self, broker_event: Mapping[str, Any]) -> NormalizedEvent:
        normalized: dict[str, Any] = {}
        for canonical_field in NormalizedEvent.model_fields:
            source_field = self._field_map.get(canonical_field, canonical_field)
            if source_field in broker_event:
                normalized[canonical_field] = broker_event[source_field]
        event_type = normalized.get("event_type")
        if isinstance(event_type, str) and event_type in self._event_type_map:
            normalized["event_type"] = self._event_type_map[event_type]
        return NormalizedEvent.model_validate(normalized)


class EventSource(ABC):
    """Produces a stream of raw trading events for downstream processing."""

    @abstractmethod
    def events(self) -> Iterator[dict[str, Any]]:
        """Yield raw events one at a time."""
        raise NotImplementedError
