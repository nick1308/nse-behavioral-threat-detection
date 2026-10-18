from datetime import datetime, timezone

import pytest

from threat_detection.detection.base import AnomalyDetector
from threat_detection.evaluation.harness import evaluate, fit_isolation_forest
from threat_detection.ingestion.base import EventSource


class _FixedEventSource(EventSource):
    def __init__(self, events):
        self._events = events

    def events(self):
        yield from self._events


class _RecordingDetector(AnomalyDetector):
    def __init__(self, risk_score=0.0):
        self.risk_score = risk_score
        self.seen_features = []

    def score(self, features):
        self.seen_features.append(features)
        return {"risk_score": self.risk_score, "explanation": "test", "attack_type_guess": None}


def _event(event_id, is_attack=False, attack_type=None):
    return {
        "event_id": event_id,
        "account_id": "ACC0001",
        "timestamp": datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc).isoformat(),
        "event_type": "LOGIN",
        "device_id": "device-1",
        "ip_address": "10.0.0.1",
        "session_id": "sess-1",
        "is_attack": is_attack,
        "attack_type": attack_type,
    }


def test_labels_are_not_passed_to_feature_extractor_or_detector():
    class RecordingExtractor:
        def __init__(self):
            self.seen_events = []

        def extract(self, event):
            self.seen_events.append(event)
            return {"value": 0.0}

    events = [_event("normal"), _event("attack", True, "api_abuse")]
    extractor = RecordingExtractor()
    detector = _RecordingDetector()

    evaluate(_FixedEventSource(events), feature_extractor=extractor, detector=detector)

    for received in extractor.seen_events:
        assert "is_attack" not in received
        assert "attack_type" not in received
    assert detector.seen_features == [{"value": 0.0}, {"value": 0.0}]


def test_metrics_are_correct_for_a_small_hand_built_example():
    events = [
        _event("normal-1"),
        _event("normal-2"),
        _event("takeover", True, "account_takeover"),
        _event("api", True, "api_abuse"),
        _event("automated", True, "automated_trading"),
    ]
    # At threshold 50, two of three attacks and one of two normal events alert.
    class _SequenceDetector(AnomalyDetector):
        def __init__(self):
            self.scores = iter([0.0, 75.0, 50.0, 20.0, 100.0])

        def score(self, features):
            return {"risk_score": next(self.scores)}

    report = evaluate(_FixedEventSource(events), detector=_SequenceDetector())

    assert report["total_events"] == 5
    assert report["actual_attacks"] == 3
    assert report["normal_events"] == 2
    assert report["true_positives"] == 2
    assert report["false_positives"] == 1
    assert report["recall"] == pytest.approx(2 / 3)
    assert report["false_positive_rate"] == pytest.approx(1 / 2)
    assert report["per_attack_type_recall"] == {
        "account_takeover": 1.0,
        "api_abuse": 0.0,
        "automated_trading": 1.0,
    }
    assert report["latency_ms"]["mean"] >= 0.0
    assert report["latency_ms"]["p95"] >= 0.0


def test_threshold_must_be_between_zero_and_one_hundred():
    with pytest.raises(ValueError, match="threshold"):
        evaluate(_FixedEventSource([]), threshold=101.0)


def test_scenario_recall_counts_one_detected_event_for_a_multi_event_attack():
    events = [
        _event("takeover-login", True, "account_takeover"),
        _event("takeover-device", True, "account_takeover"),
        _event("takeover-order", True, "account_takeover"),
    ]

    class _SequenceDetector(AnomalyDetector):
        def __init__(self):
            self.scores = iter([0.0, 0.0, 75.0])

        def score(self, features):
            return {"risk_score": next(self.scores)}

    report = evaluate(_FixedEventSource(events), detector=_SequenceDetector())

    assert report["recall"] == 1.0
    assert report["event_recall"] == pytest.approx(1 / 3)
    assert report["attack_scenarios"] == 1
    assert report["per_attack_type_recall"]["account_takeover"] == 1.0


def test_isolation_forest_training_discards_ground_truth_labels_before_extraction():
    class RecordingExtractor:
        def __init__(self):
            self.seen_events = []

        def extract(self, event):
            self.seen_events.append(event)
            return {"is_new_device": 0.0}

    events = [_event("normal-1"), _event("normal-2")]
    extractor = RecordingExtractor()
    detector, training_count = fit_isolation_forest(
        _FixedEventSource(events), feature_extractor=extractor
    )

    assert training_count == 2
    assert all("is_attack" not in event and "attack_type" not in event for event in extractor.seen_events)
    assert detector.score({"is_new_device": 0.0})["risk_score"] == 0.0
