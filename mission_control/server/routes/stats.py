"""Statistics and health check endpoints."""

from __future__ import annotations

import time
from typing import Dict

from fastapi import APIRouter, Request
from pydantic import BaseModel

router = APIRouter()

_start_time = time.time()


class HealthResponse(BaseModel):
    status: str = "ok"
    uptime_seconds: float = 0.0
    active_connections: int = 0


class StatsResponse(BaseModel):
    total_sessions: int = 0
    total_steps: int = 0
    verdict_distribution: Dict[str, int] = {}
    avg_alert_level: float = 0.0
    max_alert_level: float = 0.0
    blocked_count: int = 0


@router.get("/health", response_model=HealthResponse)
async def health(request: Request):
    from mission_control.server.ws import manager
    return HealthResponse(
        status="ok",
        uptime_seconds=round(time.time() - _start_time, 2),
        active_connections=manager.active_count,
    )


@router.get("/stats", response_model=StatsResponse)
async def stats(request: Request):
    mc = request.app.state.mc

    if mc.recorder is None or mc.recorder._storage is None:
        return StatsResponse()

    agg = mc.recorder._storage.get_stats()
    return StatsResponse(
        total_sessions=agg.total_sessions,
        total_steps=agg.total_steps,
        verdict_distribution=agg.verdict_distribution,
        avg_alert_level=agg.avg_alert_level,
        max_alert_level=agg.max_alert_level,
        blocked_count=agg.blocked_count,
    )
