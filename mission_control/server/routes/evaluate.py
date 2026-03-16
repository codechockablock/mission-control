"""POST /v1/evaluate -- evaluate a single action."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel

from mission_control import Action
from mission_control.server.ws import manager

router = APIRouter()


class EvaluateRequest(BaseModel):
    session_id: Optional[str] = None
    tool_type: str
    content: str
    parameters: Optional[Dict[str, Any]] = None
    source: str = "agent"


class MatchedRule(BaseModel):
    name: str
    category: str
    description: str
    severity: str


class BreakerResponse(BaseModel):
    allowed: bool
    matched_rules: List[MatchedRule]
    evaluation_time_us: int


class GovernanceResponse(BaseModel):
    step: int
    hash: str
    chain_length: int
    note: Optional[str] = None


class RecorderResponse(BaseModel):
    step: int
    verdict: str
    alert_level: float
    signals: Dict[str, float]
    context_alignment: float
    boundary_proximities: Dict[str, float]


class EvaluateResponse(BaseModel):
    allowed: bool
    blocked_by: Optional[str]
    circuit_breaker: BreakerResponse
    flight_recorder: Optional[RecorderResponse]
    governance: Optional[GovernanceResponse]


def _build_breaker_response(breaker_result) -> BreakerResponse:
    return BreakerResponse(
        allowed=breaker_result.allowed,
        matched_rules=[
            MatchedRule(
                name=r.name,
                category=r.category.value,
                description=r.description,
                severity=r.severity,
            )
            for r in breaker_result.matched_rules
        ],
        evaluation_time_us=breaker_result.evaluation_time_us,
    )


def _verdict_from_alert(alert_level: float) -> str:
    if alert_level >= 0.8:
        return "BLOCK"
    elif alert_level >= 0.5:
        return "FLAG"
    elif alert_level >= 0.2:
        return "MONITOR"
    return "PASS"


def _build_recorder_response(recorder_result) -> Optional[RecorderResponse]:
    if recorder_result is None:
        return None

    # Extract signals from the StepResult's pred_error and other fields
    pred_error = getattr(recorder_result, "pred_error", None)
    error_signal = pred_error.weighted_magnitude if pred_error else 0.0

    return RecorderResponse(
        step=recorder_result.step,
        verdict=_verdict_from_alert(recorder_result.alert_level),
        alert_level=recorder_result.alert_level,
        signals={
            "error": error_signal,
            "fisher": getattr(recorder_result, "newma_divergence", 0.0),
            "cross_slot": sum(getattr(recorder_result, "cross_term_activations", {}).values()),
            "persistence": getattr(recorder_result, "angular_disp_delta", 0.0),
            "cusum": getattr(recorder_result, "metric_trace", 0.0),
        },
        context_alignment=1.0 - getattr(recorder_result, "angular_disp_cumulative", 0.0),
        boundary_proximities=getattr(recorder_result, "boundary_proximities", {}),
    )


def _build_governance_response(mc, blocked_by: Optional[str] = None, rule_names: str = "") -> Optional[GovernanceResponse]:
    if mc.recorder is None or mc.recorder.chain is None:
        return None
    chain = mc.recorder.chain
    head = chain.head()
    if head is None:
        return GovernanceResponse(step=0, hash="", chain_length=0, note=None)
    note = None
    if blocked_by:
        note = f"BLOCKED by {blocked_by}: {rule_names}"
    return GovernanceResponse(
        step=head.seq,
        hash=head.chain_hash[:12] if head.chain_hash else "",
        chain_length=head.seq + 1,
        note=note,
    )


@router.post("/evaluate", response_model=EvaluateResponse)
async def evaluate(req: EvaluateRequest, request: Request):
    mc = request.app.state.mc

    action = Action(
        tool_type=req.tool_type,
        content=req.content,
        parameters=req.parameters,
        source=req.source,
        session_id=req.session_id,
    )

    result = mc.evaluate(action)

    breaker_resp = _build_breaker_response(result.breaker)
    recorder_resp = _build_recorder_response(result.recorder)

    rule_names = ", ".join(r.name for r in result.breaker.matched_rules)
    governance_resp = _build_governance_response(mc, result.blocked_by, rule_names)

    response = EvaluateResponse(
        allowed=result.allowed,
        blocked_by=result.blocked_by,
        circuit_breaker=breaker_resp,
        flight_recorder=recorder_resp,
        governance=governance_resp,
    )

    # Broadcast event via WebSocket
    if result.allowed:
        step = recorder_resp.step if recorder_resp else 0
        alert = recorder_resp.alert_level if recorder_resp else 0.0
        verdict = recorder_resp.verdict if recorder_resp else "PASS"
        await manager.broadcast({
            "type": "step",
            "session_id": req.session_id or "",
            "step": step,
            "verdict": verdict,
            "alert_level": alert,
        })
        if alert >= 0.8:
            await manager.broadcast({
                "type": "alert",
                "session_id": req.session_id or "",
                "alert_level": alert,
                "reasons": getattr(result.recorder, "alert_reasons", []) if result.recorder else [],
            })
    else:
        await manager.broadcast({
            "type": "block",
            "session_id": req.session_id or "",
            "step": governance_resp.step if governance_resp else 0,
            "rule": rule_names,
        })

    return response
