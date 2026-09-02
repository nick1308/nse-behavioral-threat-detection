"""Interfaces for the event ingestion layer."""

from abc import ABC, abstractmethod
from typing import Any, Iterator


class EventSource(ABC):
    """Produces a stream of raw trading events for downstream processing."""

    @abstractmethod
    def events(self) -> Iterator[dict[str, Any]]:
        """Yield raw events one at a time."""
        raise NotImplementedError
