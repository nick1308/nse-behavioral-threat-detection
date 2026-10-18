import pytest

from threat_detection.detection.zscore import ZScoreAnomalyDetector
from threat_detection.evaluation.harness import evaluate
from threat_detection.evaluation.variants import ATTACK_VARIANTS, AttackVariantEventSource


@pytest.mark.parametrize("attack_type", ATTACK_VARIANTS)
def test_curated_lower_intensity_attack_variants_reach_review_threshold(attack_type):
    report = evaluate(AttackVariantEventSource(attack_type), detector=ZScoreAnomalyDetector())

    assert report["attack_scenarios"] == 1
    assert report["recall"] == 1.0
    assert report["event_recall"] > 0.0
    assert report["false_positive_rate"] == 0.0


def test_curated_variant_source_rejects_unknown_attack_type():
    with pytest.raises(ValueError, match="unsupported attack variant"):
        AttackVariantEventSource("unknown")
