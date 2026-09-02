"""Interfaces for the anomaly detection layer."""

from abc import ABC, abstractmethod
from typing import Any


class AnomalyDetector(ABC):
    """Scores a feature vector for anomalousness and returns an explainable risk score."""

    @abstractmethod
    def score(self, features: dict[str, float]) -> dict[str, Any]:
        """Return a risk score and supporting explanation for the given features."""
        raise NotImplementedError
