from threat_detection.features.base import FeatureExtractor


def test_feature_extractor_is_abstract():
    assert FeatureExtractor.__abstractmethods__ == frozenset({"extract"})
