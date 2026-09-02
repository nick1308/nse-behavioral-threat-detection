from threat_detection.detection.base import AnomalyDetector


def test_anomaly_detector_is_abstract():
    assert AnomalyDetector.__abstractmethods__ == frozenset({"score"})
