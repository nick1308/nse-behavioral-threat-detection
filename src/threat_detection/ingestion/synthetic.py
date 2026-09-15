"""Synthetic event generator — a concrete EventSource.

Simulates a small population of trading accounts behaving normally, with a
handful of accounts carrying a planted attack (account takeover, API abuse,
or automated trading — see DECISIONS.md §8 for the concrete signal each
attack is built from).

Every event carries `is_attack` / `attack_type` ground truth (EVENT_SCHEMA.md
"Ground-truth labeling" section). This ground truth is for the EVALUATION
HARNESS ONLY — the detection pipeline (features/detection layers) must never
read these two fields, since a detector that could see them would be
solving a different, easier problem than the one it's meant to solve.
"""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from threat_detection.ingestion.base import EventSource

# A small universe of symbols to trade — enough variety to look real,
# small enough to keep feature baselines meaningful within a short demo run.
_SYMBOLS = ["RELIANCE", "TCS", "INFY", "HDFCBANK", "ICICIBANK", "SBIN", "ITC", "LT"]

_ATTACK_TYPES = ("account_takeover", "api_abuse", "automated_trading")


def _seeded_uuid(rng: random.Random) -> str:
    """UUID-looking id drawn from the generator's own seeded RNG, so that
    two runs with the same seed produce byte-identical output. `uuid.uuid4()`
    uses the OS's own entropy source and is never reproducible, even with a
    seeded `random.Random` elsewhere in the same generator.
    """
    return str(uuid.UUID(int=rng.getrandbits(128)))


def _new_event(
    rng: random.Random,
    account_id: str,
    event_type: str,
    timestamp: datetime,
    device_id: str,
    ip_address: str,
    session_id: str,
    is_attack: bool = False,
    attack_type: str | None = None,
    **type_fields: Any,
) -> dict[str, Any]:
    """Assemble one event dict with the common fields every event carries
    (EVENT_SCHEMA.md "Common fields") plus whatever type-specific fields
    the caller passes in.
    """
    return {
        "event_id": _seeded_uuid(rng),
        "account_id": account_id,
        "timestamp": timestamp.isoformat(),
        "event_type": event_type,
        "device_id": device_id,
        "ip_address": ip_address,
        "session_id": session_id,
        "is_attack": is_attack,
        "attack_type": attack_type if is_attack else None,
        **type_fields,
    }


@dataclass
class _AccountProfile:
    """The stable 'normal' behavior an account is generated around, so
    that later z-score/Isolation Forest layers have a real baseline to
    learn and a real deviation to catch when an attack is planted.
    """

    account_id: str
    home_device_id: str
    home_ip: str
    active_hour_start: int  # this account normally trades within this local-hour window
    active_hour_end: int
    typical_order_qty: int
    typical_symbols: list[str] = field(default_factory=list)


class SyntheticEventSource(EventSource):
    """Generates a bounded, deterministic-if-seeded stream of synthetic
    trading events for a fixed population of accounts, planting a small
    number of labeled attacks among otherwise-normal behavior.
    """

    def __init__(
        self,
        num_accounts: int = 20,
        num_attack_accounts: int = 4,
        events_per_normal_account: int = 40,
        seed: int | None = 42,
        start_time: datetime | None = None,
    ) -> None:
        if num_attack_accounts > num_accounts:
            raise ValueError("num_attack_accounts cannot exceed num_accounts")
        self._rng = random.Random(seed)
        self._num_accounts = num_accounts
        self._num_attack_accounts = num_attack_accounts
        self._events_per_normal_account = events_per_normal_account
        self._start_time = start_time or datetime.now(timezone.utc) - timedelta(days=30)
        self._profiles = self._build_profiles()
        # First N profiles (by account index) get an attack planted on them;
        # which attack type cycles through the three known patterns.
        self._attack_account_ids = {
            p.account_id for p in self._profiles[:num_attack_accounts]
        }

    # -- EventSource interface -------------------------------------------------

    def events(self) -> Iterator[dict[str, Any]]:
        all_events: list[tuple[datetime, dict[str, Any]]] = []

        for profile in self._profiles:
            normal_events = self._generate_normal_history(profile)
            all_events.extend((self._parse_ts(e), e) for e in normal_events)

            if profile.account_id in self._attack_account_ids:
                attack_type = self._assign_attack_type(profile)
                attack_events = self._generate_attack(profile, attack_type)
                all_events.extend((self._parse_ts(e), e) for e in attack_events)

        # Yield in chronological order, the way a real event source would.
        all_events.sort(key=lambda pair: pair[0])
        for _, event in all_events:
            yield event

    # -- profile / population setup --------------------------------------------

    def _build_profiles(self) -> list[_AccountProfile]:
        profiles = []
        for i in range(self._num_accounts):
            account_id = f"ACC{i:04d}"
            active_start = self._rng.randint(6, 12)
            profiles.append(
                _AccountProfile(
                    account_id=account_id,
                    home_device_id=f"device-{self._rng.getrandbits(32):08x}",
                    home_ip=f"10.{self._rng.randint(0,255)}.{self._rng.randint(0,255)}.{self._rng.randint(1,254)}",
                    active_hour_start=active_start,
                    active_hour_end=min(active_start + self._rng.randint(4, 8), 23),
                    typical_order_qty=self._rng.choice([10, 25, 50, 100, 200]),
                    typical_symbols=self._rng.sample(_SYMBOLS, k=self._rng.randint(1, 3)),
                )
            )
        return profiles

    def _assign_attack_type(self, profile: _AccountProfile) -> str:
        # Cycle through the three known attack types in the order attack
        # accounts were selected, so a given seed always produces the same
        # mix (Python's built-in hash() is salted per-process and is NOT
        # reproducible across runs — using it here would silently break
        # the reproducibility guarantee this generator promises).
        ordered_attack_ids = [p.account_id for p in self._profiles[: self._num_attack_accounts]]
        idx = ordered_attack_ids.index(profile.account_id)
        return _ATTACK_TYPES[idx % len(_ATTACK_TYPES)]

    @staticmethod
    def _parse_ts(event: dict[str, Any]) -> datetime:
        return datetime.fromisoformat(event["timestamp"])

    # -- normal behavior generation ---------------------------------------------

    def _generate_normal_history(self, profile: _AccountProfile) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        session_id = _seeded_uuid(self._rng)
        current = self._start_time + timedelta(
            days=self._rng.randint(0, 25),
            hours=profile.active_hour_start,
            minutes=self._rng.randint(0, 59),
        )

        events.append(
            _new_event(
                self._rng,
                profile.account_id,
                "LOGIN",
                current,
                profile.home_device_id,
                profile.home_ip,
                session_id,
                success=True,
                auth_method="mfa",
            )
        )

        for _ in range(self._events_per_normal_account):
            current += timedelta(minutes=self._rng.uniform(1, 15))
            symbol = self._rng.choice(profile.typical_symbols)

            if self._rng.random() < 0.6:
                # Normal order sized close to the account's typical quantity —
                # this is exactly the baseline the z-score layer learns.
                qty = max(1, int(self._rng.gauss(profile.typical_order_qty, profile.typical_order_qty * 0.15)))
                price = round(self._rng.uniform(100, 4000), 2)
                events.append(
                    _new_event(
                        self._rng,
                        profile.account_id,
                        "ORDER",
                        current,
                        profile.home_device_id,
                        profile.home_ip,
                        session_id,
                        symbol=symbol,
                        order_type=self._rng.choice(["buy", "sell"]),
                        quantity=qty,
                        price=price,
                        order_value=round(qty * price, 2),
                    )
                )
            else:
                events.append(
                    _new_event(
                        self._rng,
                        profile.account_id,
                        "VIEW_STOCK",
                        current,
                        profile.home_device_id,
                        profile.home_ip,
                        session_id,
                        symbol=symbol,
                    )
                )

        current += timedelta(minutes=self._rng.uniform(1, 20))
        events.append(
            _new_event(
                self._rng,
                profile.account_id, "LOGOUT", current, profile.home_device_id, profile.home_ip, session_id
            )
        )
        return events

    # -- attack generation --------------------------------------------------------

    def _generate_attack(self, profile: _AccountProfile, attack_type: str) -> list[dict[str, Any]]:
        if attack_type == "account_takeover":
            return self._generate_account_takeover(profile)
        if attack_type == "api_abuse":
            return self._generate_api_abuse(profile)
        if attack_type == "automated_trading":
            return self._generate_automated_trading(profile)
        raise ValueError(f"unknown attack_type: {attack_type}")

    def _generate_account_takeover(self, profile: _AccountProfile) -> list[dict[str, Any]]:
        """Signal (DECISIONS.md §8): new/unseen device AND login outside the
        account's historical time window AND order size far above historical
        max, all within a short time span.
        """
        events: list[dict[str, Any]] = []
        attack_day = self._start_time + timedelta(days=self._rng.randint(26, 29))
        # Deliberately outside [active_hour_start, active_hour_end] and on an
        # unseen device/IP — that combination is the anomaly, not any one field.
        off_hour = (profile.active_hour_end + 6) % 24
        t = attack_day.replace(hour=off_hour, minute=self._rng.randint(0, 59))

        unseen_device = f"device-{self._rng.getrandbits(32):08x}"
        unseen_ip = f"185.{self._rng.randint(0,255)}.{self._rng.randint(0,255)}.{self._rng.randint(1,254)}"
        session_id = _seeded_uuid(self._rng)

        events.append(
            _new_event(
                self._rng,
                profile.account_id,
                "LOGIN",
                t,
                unseen_device,
                unseen_ip,
                session_id,
                is_attack=True,
                attack_type="account_takeover",
                success=True,
                auth_method="password",
            )
        )
        t += timedelta(seconds=self._rng.uniform(20, 90))
        events.append(
            _new_event(
                self._rng,
                profile.account_id,
                "DEVICE_CHANGE",
                t,
                unseen_device,
                unseen_ip,
                session_id,
                is_attack=True,
                attack_type="account_takeover",
                previous_device_id=profile.home_device_id,
                new_device_id=unseen_device,
            )
        )
        t += timedelta(seconds=self._rng.uniform(20, 90))
        # Order size far above this account's historical max (~3-6x typical).
        oversized_qty = int(profile.typical_order_qty * self._rng.uniform(4, 8))
        price = round(self._rng.uniform(100, 4000), 2)
        events.append(
            _new_event(
                self._rng,
                profile.account_id,
                "ORDER",
                t,
                unseen_device,
                unseen_ip,
                session_id,
                is_attack=True,
                attack_type="account_takeover",
                symbol=self._rng.choice(_SYMBOLS),
                order_type="sell",
                quantity=oversized_qty,
                price=price,
                order_value=round(oversized_qty * price, 2),
            )
        )
        return events

    def _generate_api_abuse(self, profile: _AccountProfile) -> list[dict[str, Any]]:
        """Signal (DECISIONS.md §8): request rate N times above the account's
        rolling baseline within a short window.
        """
        events: list[dict[str, Any]] = []
        attack_day = self._start_time + timedelta(days=self._rng.randint(26, 29))
        t = attack_day.replace(hour=profile.active_hour_start, minute=0)
        session_id = _seeded_uuid(self._rng)
        client_id = f"client-{self._rng.getrandbits(32):08x}"

        # Normal API_REQUEST baseline is roughly a handful per session; abuse
        # here is ~50 requests in under a minute — a clear rate spike.
        for _ in range(50):
            t += timedelta(milliseconds=self._rng.uniform(200, 900))
            events.append(
                _new_event(
                    self._rng,
                    profile.account_id,
                    "API_REQUEST",
                    t,
                    profile.home_device_id,
                    profile.home_ip,
                    session_id,
                    is_attack=True,
                    attack_type="api_abuse",
                    endpoint=self._rng.choice(["/quotes", "/orderbook", "/positions"]),
                    method="GET",
                    status_code=200,
                    client_id=client_id,
                )
            )
        return events

    def _generate_automated_trading(self, profile: _AccountProfile) -> list[dict[str, Any]]:
        """Signal (DECISIONS.md §8): repeated order -> cancel sequences with
        near-zero human-like timing variance (a human's cancel timing varies;
        a script's doesn't).
        """
        events: list[dict[str, Any]] = []
        attack_day = self._start_time + timedelta(days=self._rng.randint(26, 29))
        t = attack_day.replace(hour=profile.active_hour_start, minute=0)
        session_id = _seeded_uuid(self._rng)

        fixed_cancel_delay_ms = 250  # near-zero variance across every cancel: the tell
        for _ in range(15):
            t += timedelta(seconds=self._rng.uniform(2, 5))
            order_id = _seeded_uuid(self._rng)
            qty = profile.typical_order_qty
            price = round(self._rng.uniform(100, 4000), 2)
            events.append(
                {
                    **_new_event(
                        self._rng,
                        profile.account_id,
                        "ORDER",
                        t,
                        profile.home_device_id,
                        profile.home_ip,
                        session_id,
                        is_attack=True,
                        attack_type="automated_trading",
                        symbol=self._rng.choice(_SYMBOLS),
                        order_type="buy",
                        quantity=qty,
                        price=price,
                        order_value=round(qty * price, 2),
                    ),
                    "event_id": order_id,
                }
            )
            t += timedelta(milliseconds=fixed_cancel_delay_ms + self._rng.uniform(-5, 5))
            events.append(
                _new_event(
                    self._rng,
                    profile.account_id,
                    "CANCEL_ORDER",
                    t,
                    profile.home_device_id,
                    profile.home_ip,
                    session_id,
                    is_attack=True,
                    attack_type="automated_trading",
                    original_order_id=order_id,
                    time_since_order_ms=fixed_cancel_delay_ms,
                )
            )
        return events
