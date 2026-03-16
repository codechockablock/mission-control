"""Session lifecycle management for the flight recorder."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AnomalyWindow:
    """A time window where alert level exceeded threshold."""
    start_step: int
    end_step: int
    max_alert_level: float
    reasons: List[str] = field(default_factory=list)


@dataclass
class SessionSummary:
    """Summary statistics for a completed session."""
    session_id: str
    total_steps: int
    duration_seconds: float
    verdict_distribution: Dict[str, int] = field(default_factory=dict)
    max_alert_level: float = 0.0
    chain_hash: str = ""
    anomaly_windows: List[AnomalyWindow] = field(default_factory=list)
    blocked_count: int = 0


class Session:
    """
    Manages the lifecycle of a monitoring session.

    Tracks steps, alert levels, and anomaly windows.
    """

    def __init__(self, session_id: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None):
        self.session_id = session_id or f"sess_{uuid.uuid4().hex[:12]}"
        self.metadata = metadata or {}
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self._steps: List[Dict[str, Any]] = []
        self._verdicts: Dict[str, int] = {}
        self._max_alert: float = 0.0
        self._blocked_count: int = 0
        self._active = True

        # Anomaly window tracking
        self._anomaly_threshold = 0.5
        self._in_anomaly = False
        self._anomaly_start: int = 0
        self._anomaly_max: float = 0.0
        self._anomaly_reasons: List[str] = []
        self._anomaly_windows: List[AnomalyWindow] = []

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def step_count(self) -> int:
        return len(self._steps)

    def record_step(
        self,
        step_data: Dict[str, Any],
        alert_level: float = 0.0,
        alert_reasons: Optional[List[str]] = None,
        blocked: bool = False,
    ) -> None:
        """Record one step in the session."""
        if not self._active:
            raise RuntimeError(f"Session {self.session_id} is already closed")

        step_num = len(self._steps) + 1
        step_data["_step"] = step_num
        step_data["_timestamp"] = time.time()
        self._steps.append(step_data)

        # Track verdicts
        verdict = step_data.get("verdict", "UNKNOWN")
        self._verdicts[verdict] = self._verdicts.get(verdict, 0) + 1

        # Track alerts
        self._max_alert = max(self._max_alert, alert_level)
        if blocked:
            self._blocked_count += 1

        # Track anomaly windows
        if alert_level >= self._anomaly_threshold:
            if not self._in_anomaly:
                self._in_anomaly = True
                self._anomaly_start = step_num
                self._anomaly_max = alert_level
                self._anomaly_reasons = list(alert_reasons or [])
            else:
                self._anomaly_max = max(self._anomaly_max, alert_level)
                self._anomaly_reasons.extend(alert_reasons or [])
        elif self._in_anomaly:
            self._anomaly_windows.append(AnomalyWindow(
                start_step=self._anomaly_start,
                end_step=step_num - 1,
                max_alert_level=self._anomaly_max,
                reasons=list(set(self._anomaly_reasons)),
            ))
            self._in_anomaly = False

    def end(self, chain_hash: str = "") -> SessionSummary:
        """End the session and return summary."""
        if not self._active:
            raise RuntimeError(f"Session {self.session_id} is already closed")

        self._active = False
        self.end_time = time.time()

        # Close any open anomaly window
        if self._in_anomaly:
            self._anomaly_windows.append(AnomalyWindow(
                start_step=self._anomaly_start,
                end_step=len(self._steps),
                max_alert_level=self._anomaly_max,
                reasons=list(set(self._anomaly_reasons)),
            ))

        return SessionSummary(
            session_id=self.session_id,
            total_steps=len(self._steps),
            duration_seconds=self.end_time - self.start_time,
            verdict_distribution=dict(self._verdicts),
            max_alert_level=self._max_alert,
            chain_hash=chain_hash,
            anomaly_windows=list(self._anomaly_windows),
            blocked_count=self._blocked_count,
        )
