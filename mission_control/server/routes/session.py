"""Session management endpoints."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from mission_control.server.ws import manager

router = APIRouter()


class StartSessionRequest(BaseModel):
    session_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class StartSessionResponse(BaseModel):
    session_id: str
    status: str = "active"


class EndSessionResponse(BaseModel):
    session_id: str
    total_steps: int
    duration_seconds: float
    verdict_distribution: Dict[str, int]
    max_alert_level: float
    chain_hash: str
    blocked_count: int


class SessionStatusResponse(BaseModel):
    session_id: str
    is_active: bool
    step_count: int
    max_alert_level: float
    blocked_count: int


class SessionHistoryEntry(BaseModel):
    step: int = 0
    text: str = ""
    tool_type: Optional[str] = None
    verdict: str = "UNKNOWN"
    alert_level: float = 0.0
    blocked: bool = False
    timestamp: float = 0.0


class SessionHistoryResponse(BaseModel):
    session_id: str
    entries: List[SessionHistoryEntry]


@router.post("/session/start", response_model=StartSessionResponse)
async def start_session(req: StartSessionRequest, request: Request):
    mc = request.app.state.mc
    session_id = mc.start_session(session_id=req.session_id, metadata=req.metadata)

    await manager.broadcast({
        "type": "session_start",
        "session_id": session_id,
        "timestamp": mc.recorder.session.start_time if mc.recorder and mc.recorder.session else 0,
    })

    return StartSessionResponse(session_id=session_id)


@router.post("/session/end", response_model=EndSessionResponse)
async def end_session(request: Request):
    mc = request.app.state.mc
    summary = mc.end_session()
    if summary is None:
        raise HTTPException(status_code=400, detail="No active session to end")

    return EndSessionResponse(
        session_id=summary.session_id,
        total_steps=summary.total_steps,
        duration_seconds=summary.duration_seconds,
        verdict_distribution=summary.verdict_distribution,
        max_alert_level=summary.max_alert_level,
        chain_hash=summary.chain_hash,
        blocked_count=summary.blocked_count,
    )


@router.get("/session/{session_id}/status", response_model=SessionStatusResponse)
async def session_status(session_id: str, request: Request):
    mc = request.app.state.mc

    # Check if it's the current active session
    if mc.recorder and mc.recorder.session and mc.recorder.session.session_id == session_id:
        sess = mc.recorder.session
        return SessionStatusResponse(
            session_id=session_id,
            is_active=sess.is_active,
            step_count=sess.step_count,
            max_alert_level=sess._max_alert,
            blocked_count=sess._blocked_count,
        )

    # Try storage for historical sessions
    if mc.recorder and mc.recorder._storage:
        entries = mc.recorder._storage.get_session(session_id)
        if entries:
            max_alert = max((e.get("alert_level", 0.0) for e in entries), default=0.0)
            blocked = sum(1 for e in entries if e.get("blocked", False))
            return SessionStatusResponse(
                session_id=session_id,
                is_active=False,
                step_count=len(entries),
                max_alert_level=max_alert,
                blocked_count=blocked,
            )

    raise HTTPException(status_code=404, detail=f"Session {session_id} not found")


@router.get("/session/{session_id}/history", response_model=SessionHistoryResponse)
async def session_history(session_id: str, request: Request):
    mc = request.app.state.mc

    if mc.recorder and mc.recorder._storage:
        entries = mc.recorder._storage.get_session(session_id)
        if entries:
            history = [
                SessionHistoryEntry(
                    step=e.get("step", 0),
                    text=e.get("text", ""),
                    tool_type=e.get("tool_type"),
                    verdict=e.get("verdict", "UNKNOWN"),
                    alert_level=e.get("alert_level", 0.0),
                    blocked=e.get("blocked", False),
                    timestamp=e.get("timestamp", 0.0),
                )
                for e in entries
            ]
            return SessionHistoryResponse(session_id=session_id, entries=history)

    raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
