"""Rolling z-score anomaly detector — a concrete AnomalyDetector.

This is the statistical baseline described in DECISIONS.md §4: interpretable,
requires no training data, and is compared with the current Isolation Forest
layer (DECISIONS.md §3).

Combines the per-signal features from RollingStatsFeatureExtractor into a
single 0-100 risk score with a plain-English explanation, and — where the
signals line up with a known pattern — a best-guess attack_type label. That
label is a convenience for demoing/triage, not a claim of certainty: nothing
here does real attack-type classification, it just names the pattern whose
concrete signal (DECISIONS.md §8) matches best.
"""

from __future__ import annotations

from typing import Any

from threat_detection.detection.base import AnomalyDetector

# Any single feature crossing this many standard deviations is treated as
# individually suspicious. 3.0 is the conventional "clearly unusual" cutoff
# for a roughly bell-shaped distribution (~99.7% of normal values fall
# within 3 sigma) — a standard statistical rule of thumb, not something
# tuned against our own data yet (see docs/REQUIREMENTS.md NFR-1/NFR-2 on
# why our precision/recall targets are stated as working numbers).
_ZSCORE_ALERT_THRESHOLD = 3.0

# A cancel-delay variance below this (milliseconds^2) is suspiciously
# regular for human behavior — DECISIONS.md §8's "near-zero human-like
# timing variance" signal for automated trading.
_LOW_VARIANCE_THRESHOLD_MS2 = 100.0

# Weights used to combine individual signals into one 0-100 score. Kept as
# named constants (not magic numbers inline) so they're the obvious place
# to revise once real precision/recall data exists to tune against.
_WEIGHTS = {
    "device_time_takeover": 50.0,  # correlated unseen-device login and oversized order
    "order_size_zscore": 15.0,
    "api_request_rate_zscore": 30.0,
    "automated_trading": 50.0,  # repeated near-zero-variance order-cancel timing
}


class ZScoreAnomalyDetector(AnomalyDetector):
    """Concrete AnomalyDetector combining rolling z-score features into an
    explainable 0-100 risk score.
    """

    def score(self, features: dict[str, float]) -> dict[str, Any]:
        reasons: list[str] = []
        risk = 0.0
        attack_type_guess: str | None = None

        is_new_device = features.get("is_new_device", 0.0) >= 1.0
        is_new_hour = features.get("is_new_active_hour", 0.0) >= 1.0
        takeover_context = features.get("account_takeover_context", 0.0) >= 1.0
        order_size_z = features.get("order_size_zscore", 0.0)
        order_value_z = features.get("order_value_zscore", 0.0)
        order_z = max(order_size_z, order_value_z)
        api_rate_z = features.get("api_request_rate_zscore", 0.0)
        cancel_variance = features.get(
            "matched_cancel_delay_variance_ms",
            features.get("cancel_delay_variance_ms", float("inf")),
        )
        cancel_sequence_count = features.get("cancel_sequence_count", 5.0)
        market_context_suffix = ""
        if "is_regular_market_hours" in features:
            market_context = (
                "during the regular NSE weekday equity time window"
                if features["is_regular_market_hours"] >= 1.0
                else "outside the regular NSE weekday equity time window"
            )
            market_context_suffix = f" ({market_context})"

        # -- Account takeover signal (DECISIONS.md §8): new device AND new
        # active hour AND an oversized order, together, is what makes this
        # suspicious — any single one of those alone is common and benign
        # (a trader's first order of the day, or an unusually large but
        # legitimate trade). Requiring the *combination* is what keeps this
        # from being a trigger-happy false-positive machine.
        takeover_order_signal = (
            order_size_z >= _ZSCORE_ALERT_THRESHOLD
            and (takeover_context or (is_new_device and is_new_hour))
        )
        if takeover_order_signal:
            risk += _WEIGHTS["device_time_takeover"]
            if takeover_context:
                reasons.append(
                    f"order size {order_size_z:.1f}σ above the account's historical average "
                    "followed a recent login from an unseen device at an unusual hour"
                    f"{market_context_suffix}"
                )
            else:
                reasons.append(
                    f"new device and login hour for this account, combined with an order "
                    f"{order_z:.1f}σ above the account's historical average size"
                )
            attack_type_guess = "account_takeover"
        elif order_z >= _ZSCORE_ALERT_THRESHOLD:
            # Oversized order on its own is still worth a smaller score bump
            # and an explanation, just not a full takeover verdict.
            partial = _WEIGHTS["order_size_zscore"] * min(order_z / _ZSCORE_ALERT_THRESHOLD, 2.0)
            risk += partial
            if order_value_z > order_size_z:
                reasons.append(
                    f"order value {order_value_z:.1f}σ above this account's historical average"
                    f"{market_context_suffix}"
                )
            else:
                reasons.append(
                    f"order size {order_size_z:.1f}σ above this account's historical average"
                    f"{market_context_suffix}"
                )

        # -- API abuse signal (DECISIONS.md §8): request rate N times above
        # this account/client's own rolling baseline.
        if api_rate_z >= _ZSCORE_ALERT_THRESHOLD:
            partial = _WEIGHTS["api_request_rate_zscore"] * min(api_rate_z / _ZSCORE_ALERT_THRESHOLD, 2.0)
            risk += partial
            reasons.append(
                f"API request rate {api_rate_z:.1f}σ above this client's rolling baseline"
                f"{market_context_suffix}"
            )
            if attack_type_guess is None:
                attack_type_guess = "api_abuse"

        # -- Automated trading signal (DECISIONS.md §8): near-zero variance
        # in order->cancel timing. Note this is a LOW-variance alert, the
        # opposite direction from the z-score alerts above.
        if (
            cancel_sequence_count >= 3
            and cancel_variance < _LOW_VARIANCE_THRESHOLD_MS2
        ):
            risk += _WEIGHTS["automated_trading"]
            reasons.append(
                f"{cancel_sequence_count:.0f} order-cancel timings are suspiciously regular "
                f"(variance {cancel_variance:.1f}ms²), "
                f"consistent with scripted rather than human cancellation"
                f"{market_context_suffix}"
            )
            attack_type_guess = "automated_trading"

        risk_score = round(min(risk, 100.0), 1)
        explanation = (
            "; ".join(reasons) if reasons else "no feature crossed an alert threshold"
        )

        return {
            "risk_score": risk_score,
            "explanation": explanation,
            "attack_type_guess": attack_type_guess,
        }
