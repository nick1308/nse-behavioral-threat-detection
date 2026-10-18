"""Run the fixed-seed baseline with ``python -m threat_detection.evaluation``."""

from datetime import datetime, timezone

from threat_detection.evaluation import evaluate, print_report
from threat_detection.evaluation.harness import fit_isolation_forest
from threat_detection.detection.ensemble import ZScoreIsolationForestEnsemble
from threat_detection.detection.zscore import ZScoreAnomalyDetector
from threat_detection.ingestion.synthetic import SyntheticEventSource


def main() -> None:
    start_time = datetime(2026, 9, 18, tzinfo=timezone.utc)
    normal_source = SyntheticEventSource(
        num_accounts=20,
        num_attack_accounts=0,
        seed=7,
        start_time=start_time,
    )
    calibration_source = SyntheticEventSource(
        num_accounts=20,
        num_attack_accounts=0,
        seed=8,
        start_time=start_time,
    )
    forest, training_events = fit_isolation_forest(
        normal_source,
        calibration_event_source=calibration_source,
        target_false_positive_rate=0.05,
    )
    print("Z-score baseline")
    report = evaluate(SyntheticEventSource(seed=42, start_time=start_time))
    print_report(report)
    print(
        f"\nIsolation Forest comparison (fit on {training_events} normal events; "
        "alert cutoff calibrated to 5% on a separate clean stream)"
    )
    forest_report = evaluate(
        SyntheticEventSource(seed=42, start_time=start_time), detector=forest
    )
    print_report(forest_report)
    print("\nCombined maximum-score layers")
    ensemble = ZScoreIsolationForestEnsemble(ZScoreAnomalyDetector(), forest)
    combined_report = evaluate(
        SyntheticEventSource(seed=42, start_time=start_time), detector=ensemble
    )
    print_report(combined_report)


if __name__ == "__main__":
    main()
