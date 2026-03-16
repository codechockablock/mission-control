"""Main FastAPI application for Mission Control server."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware

from mission_control import MissionControl
from mission_control.server.middleware import check_auth
from mission_control.server.ws import ws_endpoint
from mission_control.server.routes import evaluate, session, constitution, audit, stats


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: MissionControl instance is set by create_app or before startup
    if not hasattr(app.state, "mc"):
        app.state.mc = MissionControl()
    if not hasattr(app.state, "constitutions"):
        app.state.constitutions = {}
    yield
    # Shutdown: end any active session
    if hasattr(app.state, "mc") and app.state.mc.recorder:
        try:
            app.state.mc.end_session()
        except Exception:
            pass


def create_app(mc: Optional[MissionControl] = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Mission Control",
        description="Runtime Agent Safety Platform",
        version="0.1.0",
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Auth dependency on all /v1 routes
    app.include_router(evaluate.router, prefix="/v1", dependencies=[Depends(check_auth)])
    app.include_router(session.router, prefix="/v1", dependencies=[Depends(check_auth)])
    app.include_router(constitution.router, prefix="/v1", dependencies=[Depends(check_auth)])
    app.include_router(audit.router, prefix="/v1", dependencies=[Depends(check_auth)])
    app.include_router(stats.router, prefix="/v1", dependencies=[Depends(check_auth)])

    # WebSocket (no auth — dashboard needs it)
    app.add_api_websocket_route("/v1/ws", ws_endpoint)

    # Inject MissionControl
    if mc is not None:
        app.state.mc = mc
    app.state.constitutions = {}

    return app
