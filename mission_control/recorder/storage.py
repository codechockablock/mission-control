"""
Pluggable storage backends for the flight recorder.

Implements a Storage protocol with FileStorage (JSONL) and SQLiteStorage.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable


@dataclass
class SessionInfo:
    """Summary info for a stored session."""
    session_id: str
    start_time: float
    end_time: Optional[float] = None
    step_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AggregateStats:
    """Aggregate statistics across sessions."""
    total_sessions: int = 0
    total_steps: int = 0
    verdict_distribution: Dict[str, int] = field(default_factory=dict)
    avg_alert_level: float = 0.0
    max_alert_level: float = 0.0
    blocked_count: int = 0


@runtime_checkable
class Storage(Protocol):
    """Protocol for storage backends."""

    def append(self, session_id: str, entry: dict) -> None: ...
    def get_session(self, session_id: str) -> List[dict]: ...
    def list_sessions(self, limit: int = 100) -> List[SessionInfo]: ...
    def get_stats(self) -> AggregateStats: ...


class FileStorage:
    """JSONL file-based storage. One file per session. Good for development."""

    def __init__(self, base_dir: str = ".mission_control/sessions"):
        self._base_dir = Path(base_dir)
        self._base_dir.mkdir(parents=True, exist_ok=True)

    def _session_path(self, session_id: str) -> Path:
        # Sanitize session_id to prevent path traversal
        safe_id = session_id.replace("/", "_").replace("..", "_")
        return self._base_dir / f"{safe_id}.jsonl"

    def append(self, session_id: str, entry: dict) -> None:
        path = self._session_path(session_id)
        with open(path, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def get_session(self, session_id: str) -> List[dict]:
        path = self._session_path(session_id)
        if not path.exists():
            return []
        entries = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    def list_sessions(self, limit: int = 100) -> List[SessionInfo]:
        sessions = []
        if not self._base_dir.exists():
            return sessions
        files = sorted(self._base_dir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
        for f in files[:limit]:
            session_id = f.stem
            stat = f.stat()
            entries = self.get_session(session_id)
            sessions.append(SessionInfo(
                session_id=session_id,
                start_time=stat.st_ctime,
                end_time=stat.st_mtime,
                step_count=len(entries),
            ))
        return sessions

    def get_stats(self) -> AggregateStats:
        sessions = self.list_sessions(limit=10000)
        stats = AggregateStats(total_sessions=len(sessions))
        total_alert = 0.0
        for si in sessions:
            entries = self.get_session(si.session_id)
            stats.total_steps += len(entries)
            for entry in entries:
                alert = entry.get("alert_level", 0.0)
                if isinstance(alert, (int, float)):
                    stats.max_alert_level = max(stats.max_alert_level, alert)
                    total_alert += alert
                verdict = entry.get("verdict", "UNKNOWN")
                stats.verdict_distribution[verdict] = stats.verdict_distribution.get(verdict, 0) + 1
                blocked = entry.get("blocked", False)
                if blocked:
                    stats.blocked_count += 1
        if stats.total_steps > 0:
            stats.avg_alert_level = total_alert / stats.total_steps
        return stats


class SQLiteStorage:
    """SQLite-based storage. Good for single-server production."""

    def __init__(self, db_path: str = ".mission_control/mission_control.db"):
        db_file = Path(db_path)
        db_file.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_file), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()

    def _create_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                start_time REAL NOT NULL,
                end_time REAL,
                metadata TEXT DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                data TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            );
            CREATE INDEX IF NOT EXISTS idx_entries_session ON entries(session_id);
        """)
        self._conn.commit()

    def _ensure_session(self, session_id: str) -> None:
        row = self._conn.execute(
            "SELECT session_id FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO sessions (session_id, start_time) VALUES (?, ?)",
                (session_id, time.time()),
            )
            self._conn.commit()

    def append(self, session_id: str, entry: dict) -> None:
        self._ensure_session(session_id)
        self._conn.execute(
            "INSERT INTO entries (session_id, timestamp, data) VALUES (?, ?, ?)",
            (session_id, time.time(), json.dumps(entry, default=str)),
        )
        self._conn.commit()

    def get_session(self, session_id: str) -> List[dict]:
        rows = self._conn.execute(
            "SELECT data FROM entries WHERE session_id = ? ORDER BY id", (session_id,)
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def list_sessions(self, limit: int = 100) -> List[SessionInfo]:
        rows = self._conn.execute(
            "SELECT s.session_id, s.start_time, s.end_time, s.metadata, COUNT(e.id) "
            "FROM sessions s LEFT JOIN entries e ON s.session_id = e.session_id "
            "GROUP BY s.session_id ORDER BY s.start_time DESC LIMIT ?",
            (limit,),
        ).fetchall()
        sessions = []
        for row in rows:
            meta = json.loads(row[3]) if row[3] else {}
            sessions.append(SessionInfo(
                session_id=row[0],
                start_time=row[1],
                end_time=row[2],
                step_count=row[4],
                metadata=meta,
            ))
        return sessions

    def get_stats(self) -> AggregateStats:
        total_sessions = self._conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        total_steps = self._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        return AggregateStats(
            total_sessions=total_sessions,
            total_steps=total_steps,
        )

    def close(self) -> None:
        self._conn.close()
