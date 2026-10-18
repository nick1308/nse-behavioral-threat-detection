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
from datetime import datetime, time, timedelta, timezone
from typing import Any

from threat_detection.features.base import FeatureExtractor

_INDIA_TIMEZONE = timezone(timedelta(hours=5, minutes=30), name="IST")
_REGULAR_SESSION_OPEN = time(9, 15)
_REGULAR_SESSION_CLOSE = time(15, 30)


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
    order_value: _WelfordStats = field(default_factory=_WelfordStats)
    event_count: int = 0
    seen_devices: set[str] = field(default_factory=set)
    seen_ips: set[str] = field(default_factory=set)
    login_hours_seen: set[int] = field(default_factory=set)
    observed_login_hours: set[int] = field(default_factory=set)
    recent_takeover_login: tuple[str, datetime] | None = None
    # Timing values from all cancel events remain available for backward
    # compatibility and analysis; the detector uses only delays tied to a
    # preceding order from the same account.
    recent_cancel_delays_ms: deque[float] = field(default_factory=lambda: deque(maxlen=20))
    recent_order_timestamps: dict[str, datetime] = field(default_factory=dict)
    matched_cancel_delays_ms: deque[float] = field(default_factory=lambda: deque(maxlen=20))
    matched_cancel_timestamps: deque[datetime] = field(default_factory=lambda: deque(maxlen=20))


@dataclass
class _APIClientState:
    """Rolling request-rate baseline for one account/API-client pair."""

    recent_request_times: deque[datetime] = field(default_factory=lambda: deque(maxlen=200))
    rate_baseline: _WelfordStats = field(default_factory=_WelfordStats)
    last_baseline_bucket: int | None = None


class RollingStatsFeatureExtractor(FeatureExtractor):
    """Concrete FeatureExtractor computing rolling per-account behavioral
    statistics, with a separate rolling request baseline per account/API
    client — the statistical/interpretable layer described in DECISIONS.md §4.
    """

    def __init__(self) -> None:
        self._accounts: dict[str, _AccountState] = {}
        self._api_clients: dict[tuple[str, str], _APIClientState] = {}

    def _state_for(self, account_id: str) -> _AccountState:
        if account_id not in self._accounts:
            self._accounts[account_id] = _AccountState()
        return self._accounts[account_id]

    def extract(self, event: dict[str, Any]) -> dict[str, float]:
        account_id = event["account_id"]
        state = self._state_for(account_id)
        event_type = event["event_type"]
        timestamp = datetime.fromisoformat(event["timestamp"])
        local_timestamp = (
            timestamp.replace(tzinfo=_INDIA_TIMEZONE)
            if timestamp.tzinfo is None
            else timestamp.astimezone(_INDIA_TIMEZONE)
        )
        # The project models the NSE normal equity window on weekdays. The
        # holiday calendar is deliberately not embedded in the feature layer.
        is_regular_market_hours = (
            local_timestamp.weekday() < 5
            and _REGULAR_SESSION_OPEN <= local_timestamp.time().replace(tzinfo=None) < _REGULAR_SESSION_CLOSE
        )
        local_hour = local_timestamp.hour
        while (
            state.matched_cancel_timestamps
            and (timestamp - state.matched_cancel_timestamps[0]).total_seconds() > 60
        ):
            state.matched_cancel_timestamps.popleft()
            state.matched_cancel_delays_ms.popleft()
        successful_login = event_type == "LOGIN" and event.get("success", True)
        is_unusual_login_hour = (
            1.0
            if successful_login
            and state.observed_login_hours
            and local_hour not in state.observed_login_hours
            else 0.0
        )
        takeover_context = 0.0
        if state.recent_takeover_login is not None:
            login_device, login_timestamp = state.recent_takeover_login
            seconds_since_login = (timestamp - login_timestamp).total_seconds()
            if 0 <= seconds_since_login <= 300 and event["device_id"] == login_device:
                takeover_context = 1.0
            elif seconds_since_login < 0 or seconds_since_login > 300:
                state.recent_takeover_login = None

        features: dict[str, float] = {
            "account_has_prior_history": 1.0 if state.event_count > 0 else 0.0,
            # Event-kind indicators give downstream models context for sparse
            # trading signals (for example, a cancel-delay statistic is only
            # meaningful on a cancellation event). These are derived features;
            # the immutable input event and the extractor interface are unchanged.
            "event_type_is_login": 1.0 if event_type == "LOGIN" else 0.0,
            "event_type_is_order": 1.0 if event_type == "ORDER" else 0.0,
            "event_type_is_cancel_order": 1.0 if event_type == "CANCEL_ORDER" else 0.0,
            "event_type_is_api_request": 1.0 if event_type == "API_REQUEST" else 0.0,
            "event_type_is_device_change": 1.0 if event_type == "DEVICE_CHANGE" else 0.0,
            "event_type_is_logout": 1.0 if event_type == "LOGOUT" else 0.0,
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
            "is_new_active_hour": 0.0 if local_hour in state.login_hours_seen else 1.0,
            "is_unusual_login_hour": is_unusual_login_hour,
            "account_takeover_context": takeover_context,
            "is_regular_market_hours": 1.0 if is_regular_market_hours else 0.0,
            "order_size_zscore": 0.0,
            "api_request_rate_zscore": 0.0,
            "cancel_sequence_count": float(len(state.matched_cancel_delays_ms)),
            # inf, not 0.0: the detector treats LOW variance as suspicious
            # (DECISIONS.md §8 — near-zero cancel-timing variance implies a
            # script). A default of 0.0 would make every non-CANCEL_ORDER
            # event look maximally suspicious by this signal, which is
            # backwards — "no cancel data for this event" must mean
            # "definitely not applicable", i.e. as far from the alert
            # threshold as possible.
            "cancel_delay_variance_ms": float("inf"),
            "matched_cancel_delay_variance_ms": self._variance(
                state.matched_cancel_delays_ms
            ),
            "order_value_zscore": 0.0,
        }

        if event_type == "ORDER":
            order_value = float(event.get("order_value", 0.0))
            order_size = float(event.get("quantity", order_value))
            features["order_size_zscore"] = state.order_size.zscore(order_size)
            state.order_size.update(order_size)
            if "order_value" in event:
                features["order_value_zscore"] = state.order_value.zscore(order_value)
                state.order_value.update(order_value)
            order_id = str(event.get("event_id", ""))
            if order_id:
                state.recent_order_timestamps[order_id] = timestamp
                if len(state.recent_order_timestamps) > 200:
                    oldest_order_id = next(iter(state.recent_order_timestamps))
                    del state.recent_order_timestamps[oldest_order_id]

        elif event_type == "API_REQUEST":
            client_id = str(event.get("client_id") or account_id)
            client_state = self._api_clients.setdefault(
                (account_id, client_id), _APIClientState()
            )
            client_state.recent_request_times.append(timestamp)
            rate = self._current_request_rate(client_state, timestamp)
            features["api_request_rate_zscore"] = client_state.rate_baseline.zscore(rate)
            current_bucket = int(timestamp.timestamp() // 60)
            if current_bucket != client_state.last_baseline_bucket:
                # Only fold the rate into the baseline once per minute of
                # real time has elapsed, so an in-progress burst can't
                # retrain the baseline to think the burst is normal.
                client_state.rate_baseline.update(rate)
                client_state.last_baseline_bucket = current_bucket

        elif event_type == "CANCEL_ORDER":
            delay_ms = float(event.get("time_since_order_ms", 0))
            state.recent_cancel_delays_ms.append(delay_ms)
            original_order_id = str(event.get("original_order_id", ""))
            order_timestamp = state.recent_order_timestamps.pop(original_order_id, None)
            if order_timestamp is not None:
                observed_delay_ms = (timestamp - order_timestamp).total_seconds() * 1000.0
                if 0 <= observed_delay_ms <= 30_000:
                    state.matched_cancel_delays_ms.append(observed_delay_ms)
                    state.matched_cancel_timestamps.append(timestamp)
            features["cancel_sequence_count"] = float(len(state.matched_cancel_delays_ms))
            features["matched_cancel_delay_variance_ms"] = self._variance(
                state.matched_cancel_delays_ms
            )
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
        state.login_hours_seen.add(local_hour)
        if successful_login:
            if state.observed_login_hours and features["is_new_device"] and is_unusual_login_hour:
                state.recent_takeover_login = (event["device_id"], timestamp)
            state.observed_login_hours.add(local_hour)

        state.event_count += 1

        return features

    @staticmethod
    def _current_request_rate(state: _APIClientState, now: datetime) -> float:
        """Requests in the trailing 60 seconds, as of `now`."""
        window_start = now.timestamp() - 60.0
        return sum(1 for t in state.recent_request_times if t.timestamp() >= window_start)

    @staticmethod
    def _variance(values: deque[float]) -> float:
        if len(values) < 2:
            return float("inf")  # not enough data to call it "suspiciously low" yet
        mean = sum(values) / len(values)
        return sum((v - mean) ** 2 for v in values) / (len(values) - 1)
