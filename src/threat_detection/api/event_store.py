"""SQLite persistence for compact scored-event history."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from threading import RLock
from typing import Any


class SQLiteEventStore:
    """Persist recent analyst-facing score summaries in a local SQLite file.

    Only the compact event summary passed to :meth:`append` is stored. Raw
    broker payloads and evaluation labels are not persisted by this store.
    """

    def __init__(self, path: str | Path, *, max_events: int = 500) -> None:
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        self.path = str(path)
        self.max_events = max_events
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._connection = sqlite3.connect(
            self.path,
            timeout=10,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scored_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    UNIQUE (account_id, event_id)
                )
                """
            )

    def append(self, record: dict[str, Any]) -> None:
        """Insert or refresh an event summary and trim history to its limit."""
        record_json = json.dumps(record, separators=(",", ":"), allow_nan=False)
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO scored_events (event_id, account_id, record_json)
                VALUES (?, ?, ?)
                ON CONFLICT (account_id, event_id)
                DO UPDATE SET record_json = excluded.record_json
                """,
                (record["event_id"], record["account_id"], record_json),
            )
            self._connection.execute(
                """
                DELETE FROM scored_events
                WHERE id NOT IN (
                    SELECT id FROM scored_events ORDER BY id DESC LIMIT ?
                )
                """,
                (self.max_events,),
            )

    def recent(self, limit: int) -> list[dict[str, Any]]:
        """Return newest summaries first, bounded by the requested limit."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT record_json FROM scored_events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [json.loads(row["record_json"]) for row in rows]

    def close(self) -> None:
        with self._lock:
            self._connection.close()
