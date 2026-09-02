"""Interfaces for the feature extraction layer."""

from abc import ABC, abstractmethod
from typing import Any


class FeatureExtractor(ABC):
    """Transforms a raw event (or window of events) into a behavioral feature vector."""

    @abstractmethod
    def extract(self, event: dict[str, Any]) -> dict[str, float]:
        """Return a named feature vector for the given event."""
        raise NotImplementedError
