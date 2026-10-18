"""Replay labeled synthetic events through the unlabeled detection pipeline.

Ground-truth labels are read only after extraction and scoring. Attack recall
is scenario-level: a planted account/type scenario is detected if at least
one of its events reaches the risk threshold. Event-level recall is also
reported. Per-type recall is scenario-level. Latencies measure the
extractor-plus-detector time for each event, in milliseconds.
"""

from __future__ import annotations

import math
from statistics import fmean
from time import perf_counter
from typing import Any

from threat_detection.detection.zscore import ZScoreAnomalyDetector
from threat_detection.detection.isolation_forest import IsolationForestAnomalyDetector
from threat_detection.features.rolling_stats import RollingStatsFeatureExtractor
from threat_detection.ingestion.base import EventSource

_ATTACK_TYPES = ("account_takeover", "api_abuse", "automated_trading")


def fit_isolation_forest(
    normal_event_source: EventSource,
    *,
    calibration_event_source: EventSource | None = None,
    target_false_positive_rate: float = 0.05,
    feature_extractor: RollingStatsFeatureExtractor | None = None,
    detector: IsolationForestAnomalyDetector | None = None,
) -> tuple[IsolationForestAnomalyDetector, int]:
    """Fit an Isolation Forest using only a separate normal-history source.

    Labels are discarded before extraction, including for this training pass.
    The caller is responsible for constructing a source that contains no
    planted attacks; labels are never consulted to select training rows.
    """
    extractor = feature_extractor or RollingStatsFeatureExtractor()
    anomaly_detector = detector or IsolationForestAnomalyDetector()
    feature_vectors = []
    for labeled_event in normal_event_source.events():
        event = {
            key: value for key, value in labeled_event.items()
            if key not in {"is_attack", "attack_type"}
        }
        feature_vectors.append(extractor.extract(event))
    anomaly_detector.fit(feature_vectors)
    if calibration_event_source is not None:
        calibration_extractor = RollingStatsFeatureExtractor()
        calibration_vectors = []
        for labeled_event in calibration_event_source.events():
            event = {
                key: value for key, value in labeled_event.items()
                if key not in {"is_attack", "attack_type"}
            }
            calibration_vectors.append(calibration_extractor.extract(event))
        anomaly_detector.calibrate(
            calibration_vectors,
            target_false_positive_rate=target_false_positive_rate,
        )
    return anomaly_detector, len(feature_vectors)


def _rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _percentile_95(values: list[float]) -> float:
    """Return the nearest-rank 95th percentile (rank ceil(0.95 * n))."""
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def evaluate(
    event_source: EventSource,
    threshold: float = 50.0,
    feature_extractor: RollingStatsFeatureExtractor | None = None,
    detector: ZScoreAnomalyDetector | None = None,
) -> dict[str, Any]:
    """Replay an event source and return scenario/event metrics and latency.

    The same extractor and detector instances are used for the entire ordered
    stream so their per-account history is preserved. The ground-truth keys
    ``is_attack`` and ``attack_type`` are removed before either component is
    called. An event is predicted as an attack when ``risk_score >= threshold``.
    """
    if not 0.0 <= threshold <= 100.0:
        raise ValueError("threshold must be between 0 and 100")

    extractor = (
        feature_extractor
        if feature_extractor is not None
        else RollingStatsFeatureExtractor()
    )
    anomaly_detector = detector if detector is not None else ZScoreAnomalyDetector()
    total_events = 0
    actual_attacks = 0
    true_positives = 0
    false_positives = 0
    normal_events = 0
    attack_scenarios: dict[tuple[str, str], bool] = {}
    latencies_ms: list[float] = []

    for labeled_event in event_source.events():
        # Capture labels for metric bookkeeping, then build a separate payload
        # so neither downstream component can observe synthetic ground truth.
        is_attack = bool(labeled_event.get("is_attack", False))
        attack_type = labeled_event.get("attack_type") if is_attack else None
        event = {
            key: value
            for key, value in labeled_event.items()
            if key not in {"is_attack", "attack_type"}
        }

        started_at = perf_counter()
        features = extractor.extract(event)
        result = anomaly_detector.score(features)
        latencies_ms.append((perf_counter() - started_at) * 1000.0)

        predicted_attack = float(result["risk_score"]) >= threshold
        total_events += 1
        if is_attack:
            actual_attacks += 1
            scenario_type = str(attack_type or "unknown")
            scenario_key = (str(event["account_id"]), scenario_type)
            attack_scenarios.setdefault(scenario_key, False)
            if predicted_attack:
                attack_scenarios[scenario_key] = True
            if predicted_attack:
                true_positives += 1
        else:
            normal_events += 1
            if predicted_attack:
                false_positives += 1

    return {
        "threshold": float(threshold),
        "total_events": total_events,
        "actual_attacks": actual_attacks,
        "normal_events": normal_events,
        "predicted_attacks": true_positives + false_positives,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "recall": _rate(sum(attack_scenarios.values()), len(attack_scenarios)),
        "event_recall": _rate(true_positives, actual_attacks),
        "false_positive_rate": _rate(false_positives, normal_events),
        "per_attack_type_recall": {
            attack_type: _rate(
                sum(
                    detected
                    for (_, scenario_type), detected in attack_scenarios.items()
                    if scenario_type == attack_type
                ),
                sum(1 for _, scenario_type in attack_scenarios if scenario_type == attack_type),
            )
            for attack_type in _ATTACK_TYPES
        },
        "attack_scenarios": len(attack_scenarios),
        "latency_ms": {
            "mean": fmean(latencies_ms) if latencies_ms else 0.0,
            "p95": _percentile_95(latencies_ms) if latencies_ms else 0.0,
        },
    }


def print_report(report: dict[str, Any]) -> None:
    """Print the evaluation dictionary as a compact human-readable table."""
    rows = [
        ("Events", report["total_events"]),
        ("Attack-scenario recall", f"{report['recall']:.3f}"),
        ("Attack-event recall", f"{report['event_recall']:.3f}"),
        ("False-positive rate", f"{report['false_positive_rate']:.3f}"),
    ]
    rows.extend(
        (f"Recall: {attack_type}", f"{value:.3f}")
        for attack_type, value in report["per_attack_type_recall"].items()
    )
    rows.extend(
        [
            ("Mean event latency (ms)", f"{report['latency_ms']['mean']:.3f}"),
            ("95th percentile latency (ms)", f"{report['latency_ms']['p95']:.3f}"),
        ]
    )
    label_width = max(len(label) for label, _ in rows)
    value_width = max(len(str(value)) for _, value in rows)
    border = f"+{'-' * (label_width + 2)}+{'-' * (value_width + 2)}+"
    print(border)
    print(f"| {'Metric'.ljust(label_width)} | {'Value'.rjust(value_width)} |")
    print(border)
    for label, value in rows:
        print(f"| {label.ljust(label_width)} | {str(value).rjust(value_width)} |")
    print(border)
