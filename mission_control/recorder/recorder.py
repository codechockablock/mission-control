"""
FlightRecorder — thin wrapper around frontier-ops FullPipeline.

Provides session lifecycle, storage, and governance chain integration.
"""

from __future__ import annotations

import uuid
import time
from typing import Any, Dict, List, Optional

from frontier_ops.pipeline import FullPipeline, StepResult
from frontier_ops.boundary.constitution import ConstitutionSpec
from frontier_ops.governance.chain import GovernanceChain, GovernanceAuditor

from mission_control.recorder.session import Session, SessionSummary
from mission_control.recorder.storage import Storage, FileStorage


class FlightRecorder:
    """
    Flight recorder wrapping frontier-ops FullPipeline + GovernanceChain.

    Records every action through the full geometric pipeline and signs
    each observation to the governance chain.
    """

    def __init__(
        self,
        constitution: Optional[ConstitutionSpec] = None,
        storage: Optional[Storage] = None,
        enable_governance: bool = True,
    ):
        self._constitution = constitution or ConstitutionSpec.agent_safety_default()
        self._storage = storage or FileStorage()
        self._enable_governance = enable_governance

        # Pipeline does its own governance; we maintain a separate chain for
        # mission-control-level observations (including blocked actions)
        self._pipeline = FullPipeline(
            constitution=self._constitution,
            enable_governance=False,  # We handle governance ourselves
        )
        self._chain = GovernanceChain() if enable_governance else None

        # Session state
        self._session: Optional[Session] = None

    @property
    def chain(self) -> Optional[GovernanceChain]:
        return self._chain

    @property
    def pipeline(self) -> FullPipeline:
        return self._pipeline

    @property
    def session(self) -> Optional[Session]:
        return self._session

    def start_session(
        self,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Begin a new monitoring session."""
        if self._session is not None and self._session.is_active:
            self.end_session()

        self._pipeline.reset()
        self._session = Session(session_id=session_id, metadata=metadata)

        # Sign session start to governance chain
        if self._chain is not None:
            self._chain.observe({
                "event": "session_start",
                "session_id": self._session.session_id,
                "timestamp": self._session.start_time,
            })

        return self._session.session_id

    def record(
        self,
        text: str,
        tool_type: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> StepResult:
        """Record and analyze one action. Signs to governance chain."""
        if self._session is None:
            self.start_session()

        # Process through frontier-ops pipeline
        result = self._pipeline.process_step(text)

        # Build storage entry
        entry = {
            "step": result.step,
            "text": text[:500],
            "tool_type": tool_type,
            "alert_level": result.alert_level,
            "alert_reasons": result.alert_reasons,
            "boundary_proximities": result.boundary_proximities,
            "angular_disp_cumulative": result.angular_disp_cumulative,
            "newma_divergence": result.newma_divergence,
            "drift_classification": result.drift_classification,
            "timestamp": time.time(),
            "metadata": metadata,
        }

        # Determine verdict string from alert level
        if result.alert_level >= 0.8:
            verdict = "ALERT"
        elif result.alert_level >= 0.3:
            verdict = "MONITOR"
        else:
            verdict = "PASS"
        entry["verdict"] = verdict

        # Sign to governance chain
        if self._chain is not None:
            self._chain.observe({
                "step": result.step,
                "alert_level": result.alert_level,
                "angular_disp": result.angular_disp_cumulative,
                "verdict": verdict,
            })

        # Store
        self._storage.append(self._session.session_id, entry)

        # Update session tracking
        self._session.record_step(
            entry,
            alert_level=result.alert_level,
            alert_reasons=result.alert_reasons,
        )

        return result

    def record_blocked(
        self,
        text: str,
        rule_name: str,
        tool_type: Optional[str] = None,
    ) -> None:
        """Record a blocked action to the governance chain and storage."""
        if self._session is None:
            self.start_session()

        entry = {
            "step": self._session.step_count + 1,
            "text": text[:500],
            "tool_type": tool_type,
            "blocked": True,
            "blocked_by": rule_name,
            "verdict": "BLOCKED",
            "timestamp": time.time(),
        }

        if self._chain is not None:
            self._chain.observe({
                "event": "blocked",
                "step": entry["step"],
                "blocked_by": rule_name,
            })

        self._storage.append(self._session.session_id, entry)
        self._session.record_step(entry, blocked=True)

    def end_session(self) -> Optional[SessionSummary]:
        """Finalize session, compute summary statistics."""
        if self._session is None or not self._session.is_active:
            return None

        chain_hash = ""
        if self._chain is not None:
            head = self._chain.head()
            chain_hash = head.chain_hash if head else ""
            self._chain.observe({
                "event": "session_end",
                "session_id": self._session.session_id,
                "timestamp": time.time(),
            })

        summary = self._session.end(chain_hash=chain_hash)
        return summary

    def verify_chain(self) -> bool:
        """Verify the integrity of the governance chain."""
        if self._chain is None:
            return True
        auditor = GovernanceAuditor(self._chain.public_key_hex())
        result = auditor.verify_chain(self._chain.export_chain())
        return result.valid
