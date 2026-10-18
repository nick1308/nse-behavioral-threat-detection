"""Curated variations of the synthetic attack scenarios.

These checks vary attack magnitude or timing while retaining the project's
three threat scenarios. They challenge sensitivity to the generator's exact
recipes, but are not independent broker data or evidence of real-world
generalization.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from statistics import mean, median
from typing import Any, Iterator

from threat_detection.detection.ensemble import ZScoreIsolationForestEnsemble
from threat_detection.detection.zscore import ZScoreAnomalyDetector
from threat_detection.evaluation.harness import evaluate, fit_isolation_forest, print_report
from threat_detection.features.rolling_stats import RollingStatsFeatureExtractor
from threat_detection.ingestion.base import EventSource
from threat_detection.ingestion.synthetic import SyntheticEventSource

_START_TIME = datetime(2026, 9, 18, tzinfo=timezone.utc)
_INDIA_TIMEZONE = timezone(timedelta(hours=5, minutes=30), name="IST")
ATTACK_VARIANTS = ("account_takeover", "api_abuse", "automated_trading")


class AttackVariantEventSource(EventSource):
    """Normal synthetic history followed by one lower-intensity attack variant."""

    def __init__(self, attack_type: str, *, seed: int = 42) -> None:
        if attack_type not in ATTACK_VARIANTS:
            raise ValueError(f"unsupported attack variant: {attack_type}")
        self.attack_type = attack_type
        self._normal_events = list(
            SyntheticEventSource(
                num_accounts=1,
                num_attack_accounts=0,
                events_per_normal_account=40,
                seed=seed,
                start_time=_START_TIME,
            ).events()
        )
        self._attack_events = self._build_variant()

    def events(self) -> Iterator[dict[str, Any]]:
        yield from self._normal_events
        yield from self._attack_events

    def _build_variant(self) -> list[dict[str, Any]]:
        account_id = self._normal_events[0]["account_id"]
        normal_login = next(event for event in self._normal_events if event["event_type"] == "LOGIN")
        normal_api = next(event for event in self._normal_events if event["event_type"] == "API_REQUEST")
        normal_orders = [
            event for event in self._normal_events if event["event_type"] == "ORDER"
        ]
        home_device = normal_login["device_id"]
        home_ip = normal_login["ip_address"]
        session_id = f"variant-session-{self.attack_type}"
        attack_day = (_START_TIME + timedelta(days=32)).astimezone(_INDIA_TIMEZONE)
        normal_login_hour = datetime.fromisoformat(normal_login["timestamp"]).astimezone(
            _INDIA_TIMEZONE
        ).hour
        attack_hour = (normal_login_hour + 12) % 24
        attack_time = attack_day.replace(hour=attack_hour, minute=0, second=0, microsecond=0)

        if self.attack_type == "account_takeover":
            typical_quantity = mean(float(event["quantity"]) for event in normal_orders)
            typical_price = median(float(event["price"]) for event in normal_orders)
            quantity = max(1, round(typical_quantity * 2.0))
            device_id = f"device-variant-{self.attack_type}"
            ip_address = "185.10.20.30"
            order_time = attack_time + timedelta(minutes=1)
            return [
                self._attack_event(
                    "variant-login",
                    account_id,
                    attack_time,
                    "LOGIN",
                    device_id,
                    ip_address,
                    session_id,
                    success=True,
                    auth_method="password",
                ),
                self._attack_event(
                    "variant-order",
                    account_id,
                    order_time,
                    "ORDER",
                    device_id,
                    ip_address,
                    session_id,
                    quantity=quantity,
                    price=typical_price,
                    order_value=quantity * typical_price,
                    symbol="TCS",
                    order_type="buy",
                ),
            ]

        if self.attack_type == "api_abuse":
            api_start = attack_time + timedelta(hours=1)
            return [
                self._attack_event(
                    f"variant-api-{index}",
                    account_id,
                    api_start + timedelta(seconds=index * 5),
                    "API_REQUEST",
                    home_device,
                    home_ip,
                    session_id,
                    endpoint="/quotes",
                    method="GET",
                    status_code=200,
                    client_id=normal_api["client_id"],
                )
                for index in range(6)
            ]

        typical_quantity = round(mean(float(event["quantity"]) for event in normal_orders))
        typical_value = mean(float(event["order_value"]) for event in normal_orders)
        typical_price = typical_value / max(1, typical_quantity)
        cancel_delays_ms = (243, 257, 244, 256, 246, 254)
        events: list[dict[str, Any]] = []
        pair_start = attack_time + timedelta(hours=2)
        for index, delay_ms in enumerate(cancel_delays_ms):
            order_id = f"variant-order-{index}"
            order_time = pair_start + timedelta(seconds=index * 4)
            events.append(
                self._attack_event(
                    order_id,
                    account_id,
                    order_time,
                    "ORDER",
                    home_device,
                    home_ip,
                    session_id,
                    quantity=typical_quantity,
                    price=typical_price,
                    order_value=typical_value,
                    symbol="TCS",
                    order_type="buy",
                )
            )
            events.append(
                self._attack_event(
                    f"variant-cancel-{index}",
                    account_id,
                    order_time + timedelta(milliseconds=delay_ms),
                    "CANCEL_ORDER",
                    home_device,
                    home_ip,
                    session_id,
                    original_order_id=order_id,
                    time_since_order_ms=delay_ms,
                )
            )
        return events

    def _attack_event(
        self,
        event_id: str,
        account_id: str,
        timestamp: datetime,
        event_type: str,
        device_id: str,
        ip_address: str,
        session_id: str,
        **fields: Any,
    ) -> dict[str, Any]:
        return {
            "event_id": event_id,
            "account_id": account_id,
            "timestamp": timestamp.isoformat(),
            "event_type": event_type,
            "device_id": device_id,
            "ip_address": ip_address,
            "session_id": session_id,
            "is_attack": True,
            "attack_type": self.attack_type,
            **fields,
        }


class BenignMfaTakeoverLikeEventSource(EventSource):
    """A constructed legitimate-looking event chain with successful MFA.

    The scenario intentionally overlaps account-takeover behavior signals so
    the evaluation can reveal whether the scoring explanation preserves
    relevant authentication context. Its labels describe this fixture only;
    they are not inferred from real user activity.
    """

    def __init__(self, *, seed: int = 42) -> None:
        self._source = AttackVariantEventSource("account_takeover", seed=seed)

    def events(self) -> Iterator[dict[str, Any]]:
        for source_event in self._source.events():
            event = dict(source_event)
            if event.get("is_attack"):
                event["is_attack"] = False
                event["attack_type"] = None
                if event["event_type"] == "LOGIN":
                    event["auth_method"] = "mfa"
            yield event


def _build_combined_detector() -> ZScoreIsolationForestEnsemble:
    """Fit the demo ensemble with the same fixed normal-only streams as API."""
    normal_source = SyntheticEventSource(
        num_accounts=20,
        num_attack_accounts=0,
        seed=7,
        start_time=_START_TIME,
    )
    calibration_source = SyntheticEventSource(
        num_accounts=20,
        num_attack_accounts=0,
        seed=8,
        start_time=_START_TIME,
    )
    forest, _ = fit_isolation_forest(
        normal_source,
        calibration_event_source=calibration_source,
        target_false_positive_rate=0.05,
    )
    return ZScoreIsolationForestEnsemble(ZScoreAnomalyDetector(), forest)


def evaluate_attack_variants(
    *, detector: ZScoreIsolationForestEnsemble | None = None
) -> dict[str, dict[str, Any]]:
    """Evaluate curated variations through the current combined risk pipeline."""
    ensemble = detector or _build_combined_detector()
    return {
        attack_type: evaluate(AttackVariantEventSource(attack_type), detector=ensemble)
        for attack_type in ATTACK_VARIANTS
    }


def evaluate_benign_mfa_variation(
    *, detector: ZScoreIsolationForestEnsemble | None = None
) -> dict[str, Any]:
    """Measure alerts on the constructed MFA-authenticated benign chain."""
    ensemble = detector or _build_combined_detector()
    return evaluate(BenignMfaTakeoverLikeEventSource(), detector=ensemble)


def main() -> None:
    print("Curated synthetic attack-variation checks (not independent broker validation)")
    detector = _build_combined_detector()
    for attack_type, report in evaluate_attack_variants(detector=detector).items():
        print(f"\n{attack_type}")
        print_report(report)
    print("\nConstructed benign unusual-login/MFA context check (not a population FPR estimate)")
    print_report(evaluate_benign_mfa_variation(detector=detector))


if __name__ == "__main__":
    main()
