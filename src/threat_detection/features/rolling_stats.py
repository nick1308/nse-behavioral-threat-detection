"""Rolling per-account statistical feature extraction — a concrete FeatureExtractor.

Maintains incrementally-updated per-account state (order size mean/std, action
rate, seen devices, recent request timestamps, recent cancel delays) and turns
each incoming event into a named feature vector. This is the "interpretable
floor" layer described in DECISIONS.md §4 — every feature here is a plain
statistic an analyst could compute by hand, on purpose, so the detector built
on top of it can explain itself in plain English.

State is kept in memory, per DESIGN.md's Review-2 scope (no DB/Redis yet).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from threat_detection.features.base import FeatureExtractor


@dataclass
class _WelfordStats:
    """Streaming mean/variance via Welford's online algorithm — lets us keep a
    running mean/std of e.g. order size without storing the full history of
    every order (DESIGN.md §2 calls this out explicitly as the intended
    approach for the rolling per-account state).
    """

    count: int = 0
    mean: float = 0.0
    _m2: float = 0.0  # sum of squared differences from the current mean

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self._m2 += delta * delta2

    @property
    def std(self) -> float:
        if self.count < 2:
            return 0.0
        return (self._m2 / (self.count - 1)) ** 0.5

    def zscore(self, value: float) -> float:
        """How many standard deviations `value` is from this account's own
        historical mean.

        Two edge cases need explicit handling instead of a plain division:
        - Not enough history yet (count < 2): can't compute a meaningful
          deviation, so return 0.0 (not anomalous by default).
        - History exists but has zero variance (e.g. every request so far
          happened to be the same rate): a plain z-score would divide by
          zero. But zero variance does NOT mean any deviation is
          unmeasurable — an account whose rate has been a rock-steady 1
          request/minute and suddenly jumps to 30 is still clearly
          anomalous, so an exact repeat of the mean returns 0.0 and any
          other value returns a large fixed magnitude (signed by
          direction) rather than silently reporting "not anomalous".
        """
        if self.count < 2:
            return 0.0
        if self.std == 0:
            if value == self.mean:
                return 0.0
            return 10.0 if value > self.mean else -10.0
        return (value - self.mean) / self.std


@dataclass
class _AccountState:
    """Everything the extractor remembers about one account, built up as
    events for that account arrive.
    """

    order_size: _WelfordStats = field(default_factory=_WelfordStats)
    seen_devices: set[str] = field(default_factory=set)
    seen_ips: set[str] = field(default_factory=set)
    login_hours_seen: set[int] = field(default_factory=set)
    # Timestamps of recent API_REQUEST events, used to compute a rolling
    # request rate (DECISIONS.md §8: "request rate N x above the account's
    # rolling baseline"). Bounded so memory doesn't grow unboundedly over a
    # long-running stream.
    recent_api_request_times: deque[datetime] = field(default_factory=lambda: deque(maxlen=200))
    api_request_rate_baseline: _WelfordStats = field(default_factory=_WelfordStats)
    # Minute-bucket (epoch seconds // 60) the baseline was last updated for.
    # The baseline must only absorb one rate sample per minute of real time,
    # not one sample per request — otherwise a sustained burst of many
    # requests within a single minute updates its own baseline dozens of
    # times as it happens, and ends up chasing its own tail instead of
    # staying anchored to pre-burst normal behavior (caught by
    # test_api_request_rate_zscore_flags_a_burst).
    api_request_rate_last_bucket: int | None = None
    # Recent CANCEL_ORDER -> ORDER delays, used to catch the automated-trading
    # signal: a human's cancel timing varies, a script's doesn't
    # (DECISIONS.md §8).
    recent_cancel_delays_ms: deque[float] = field(default_factory=lambda: deque(maxlen=20))


class RollingStatsFeatureExtractor(FeatureExtractor):
    """Concrete FeatureExtractor computing rolling per-account behavioral
    statistics — the statistical/interpretable layer described in
    DECISIONS.md §4.
    """

    def __init__(self) -> None:
        self._accounts: dict[str, _AccountState] = {}

    def _state_for(self, account_id: str) -> _AccountState:
        if account_id not in self._accounts:
            self._accounts[account_id] = _AccountState()
        return self._accounts[account_id]

    def extract(self, event: dict[str, Any]) -> dict[str, float]:
        account_id = event["account_id"]
        state = self._state_for(account_id)
        event_type = event["event_type"]
        timestamp = datetime.fromisoformat(event["timestamp"])

        features: dict[str, float] = {
            # 1.0 the very first time this account uses this device/IP, else 0.0 —
            # the account-takeover signal needs "unseen device" as a hard fact,
            # not a magnitude, so this is deliberately binary rather than a
            # z-score (DECISIONS.md §8: "new/unseen device").
            "is_new_device": 0.0 if event["device_id"] in state.seen_devices else 1.0,
            "is_new_ip": 0.0 if event["ip_address"] in state.seen_ips else 1.0,
            # 1.0 if this is the first event this account has ever produced at
            # this local hour-of-day — captures "login outside the account's
            # historical time window" (DECISIONS.md §8) without needing to
            # store every past timestamp.
            "is_new_active_hour": 0.0 if timestamp.hour in state.login_hours_seen else 1.0,
            "order_size_zscore": 0.0,
            "api_request_rate_zscore": 0.0,
            # inf, not 0.0: the detector treats LOW variance as suspicious
            # (DECISIONS.md §8 — near-zero cancel-timing variance implies a
            # script). A default of 0.0 would make every non-CANCEL_ORDER
            # event look maximally suspicious by this signal, which is
            # backwards — "no cancel data for this event" must mean
            # "definitely not applicable", i.e. as far from the alert
            # threshold as possible.
            "cancel_delay_variance_ms": float("inf"),
        }

        if event_type == "ORDER":
            order_value = float(event.get("order_value", 0.0))
            features["order_size_zscore"] = state.order_size.zscore(order_value)
            state.order_size.update(order_value)

        elif event_type == "API_REQUEST":
            state.recent_api_request_times.append(timestamp)
            rate = self._current_request_rate(state, timestamp)
            features["api_request_rate_zscore"] = state.api_request_rate_baseline.zscore(rate)
            current_bucket = int(timestamp.timestamp() // 60)
            if current_bucket != state.api_request_rate_last_bucket:
                # Only fold the rate into the baseline once per minute of
                # real time has elapsed, so an in-progress burst can't
                # retrain the baseline to think the burst is normal.
                state.api_request_rate_baseline.update(rate)
                state.api_request_rate_last_bucket = current_bucket

        elif event_type == "CANCEL_ORDER":
            delay_ms = float(event.get("time_since_order_ms", 0))
            state.recent_cancel_delays_ms.append(delay_ms)
            # Low variance across recent cancel delays is itself the anomaly
            # signal (DECISIONS.md §8: "near-zero human-like timing
            # variance") — so this feature reports the *variance*, not a
            # z-score of the delay itself; the detector layer interprets
            # "suspiciously low variance" as anomalous.
            features["cancel_delay_variance_ms"] = self._variance(state.recent_cancel_delays_ms)

        # Update "seen" sets/hours AFTER computing is_new_* above, so the
        # very event that introduces a new device/IP/hour is the one that
        # correctly reports it as new (otherwise it would never fire).
        state.seen_devices.add(event["device_id"])
        state.seen_ips.add(event["ip_address"])
        state.login_hours_seen.add(timestamp.hour)

        return features

    @staticmethod
    def _current_request_rate(state: _AccountState, now: datetime) -> float:
        """Requests in the trailing 60 seconds, as of `now`."""
        window_start = now.timestamp() - 60.0
        return sum(1 for t in state.recent_api_request_times if t.timestamp() >= window_start)

    @staticmethod
    def _variance(values: deque[float]) -> float:
        if len(values) < 2:
            return float("inf")  # not enough data to call it "suspiciously low" yet
        mean = sum(values) / len(values)
        return sum((v - mean) ** 2 for v in values) / (len(values) - 1)
