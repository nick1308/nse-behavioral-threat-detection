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


class EventSource(ABC):
    """Produces a stream of raw trading events for downstream processing."""

    @abstractmethod
    def events(self) -> Iterator[dict[str, Any]]:
        """Yield raw events one at a time."""
        raise NotImplementedError
