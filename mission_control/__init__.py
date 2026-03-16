"""
Mission Control — Runtime Agent Safety Platform.

Two independent safety layers plus a tamper-evident audit trail:
1. Circuit Breaker: Categorical blocklist (regex + AST patterns, <1ms)
2. Flight Recorder: Stateful behavioral analysis (frontier-ops FullPipeline)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from mission_control.circuit_breaker import CircuitBreaker, BreakerResult
from mission_control.recorder import FlightRecorder, SessionSummary

# Lazy import — StepResult comes from frontier-ops which may not be installed
# for pure circuit-breaker usage
try:
    from frontier_ops.pipeline import StepResult
except ImportError:
    StepResult = None  # type: ignore


@dataclass
class Action:
    """An action to evaluate."""
    tool_type: str              # "shell_exec", "file_write", "sql_query", etc.
    content: str                # The action content (command, query, etc.)
    parameters: Optional[dict] = None
    source: str = "agent"       # "user" or "agent"
    session_id: Optional[str] = None


@dataclass
class EvaluationResult:
    """Combined result from circuit breaker + flight recorder."""
    allowed: bool
    blocked_by: Optional[str]   # None or "circuit_breaker"
    breaker: BreakerResult
    recorder: object = None     # StepResult or None
    timestamp: float = field(default_factory=time.time)


class MissionControl:
    """
    Main entry point. Combines circuit breaker + flight recorder.

    The circuit breaker is fast (<1ms) and categorical.
    The flight recorder is stateful and advisory.
    Both are independent — circuit breaker works without frontier-ops.
    """

    def __init__(
        self,
        circuit_breaker: Optional[CircuitBreaker] = None,
        flight_recorder: Optional[FlightRecorder] = None,
        constitution=None,
        storage=None,
    ):
        self.breaker = circuit_breaker or CircuitBreaker.default()
        if flight_recorder is not None:
            self.recorder = flight_recorder
        else:
            try:
                self.recorder = FlightRecorder(constitution=constitution, storage=storage)
            except Exception:
                self.recorder = None

    def evaluate(self, action: Action) -> EvaluationResult:
        """
        Full evaluation pipeline:
        1. Circuit breaker check (fast, categorical)
        2. If allowed, flight recorder analysis (stateful, advisory)
        3. Return combined result

        Blocked actions are still logged to governance chain.
        """
        breaker_result = self.breaker.evaluate(
            action.tool_type, action.content, action.parameters
        )

        if not breaker_result.allowed:
            # Log blocked action to governance chain
            if self.recorder is not None:
                rule_names = ", ".join(r.name for r in breaker_result.matched_rules)
                self.recorder.record_blocked(
                    action.content, rule_names, action.tool_type
                )
            return EvaluationResult(
                allowed=False,
                blocked_by="circuit_breaker",
                breaker=breaker_result,
                recorder=None,
            )

        # Run through flight recorder
        recorder_result = None
        if self.recorder is not None:
            recorder_result = self.recorder.record(
                action.content, action.tool_type
            )

        return EvaluationResult(
            allowed=True,
            blocked_by=None,
            breaker=breaker_result,
            recorder=recorder_result,
        )

    def start_session(self, session_id: str = None, metadata: dict = None) -> str:
        """Start a new monitoring session."""
        if self.recorder is not None:
            return self.recorder.start_session(session_id, metadata)
        return session_id or "no_recorder"

    def end_session(self) -> Optional[SessionSummary]:
        """End the current monitoring session."""
        if self.recorder is not None:
            return self.recorder.end_session()
        return None


__all__ = [
    "MissionControl",
    "Action",
    "EvaluationResult",
    "CircuitBreaker",
    "BreakerResult",
    "FlightRecorder",
    "SessionSummary",
]
