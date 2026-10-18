import pytest

from threat_detection.detection.zscore import ZScoreAnomalyDetector
from threat_detection.evaluation.harness import evaluate
from threat_detection.evaluation.variants import (
    AttackVariantEventSource,
    evaluate_attack_variants,
)


@pytest.mark.parametrize(
    ("attack_type", "expected_event_recall"),
    [
        ("account_takeover", 0.5),
        ("api_abuse", 5 / 6),
        ("automated_trading", 7 / 12),
    ],
)
def test_curated_attack_variants_have_expected_scenario_and_event_recall(
    attack_type, expected_event_recall
):
    report = evaluate(AttackVariantEventSource(attack_type), detector=ZScoreAnomalyDetector())

    assert report["attack_scenarios"] == 1
    assert report["recall"] == 1.0
    assert report["event_recall"] == pytest.approx(expected_event_recall)
    assert report["false_positive_rate"] == 0.0


def test_curated_variant_source_rejects_unknown_attack_type():
    with pytest.raises(ValueError, match="unsupported attack variant"):
        AttackVariantEventSource("unknown")


def test_combined_pipeline_metrics_match_the_documented_variation_check():
    reports = evaluate_attack_variants()

    assert reports["account_takeover"]["event_recall"] == 1.0
    assert reports["api_abuse"]["event_recall"] == 1.0
    assert reports["automated_trading"]["event_recall"] == pytest.approx(7 / 12)
    assert all(report["recall"] == 1.0 for report in reports.values())
    assert all(report["false_positive_rate"] == 0.0 for report in reports.values())
