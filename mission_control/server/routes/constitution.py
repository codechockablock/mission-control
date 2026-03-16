"""Constitution CRUD endpoints."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

router = APIRouter()


class ConstitutionRequest(BaseModel):
    name: str
    description: Optional[str] = ""
    principles: Optional[List[str]] = None
    boundaries: Optional[Dict[str, Any]] = None


class ConstitutionResponse(BaseModel):
    name: str
    description: str
    principles: List[str]
    boundaries: Dict[str, Any]


@router.post("/constitution", response_model=ConstitutionResponse)
async def create_constitution(req: ConstitutionRequest, request: Request):
    store = request.app.state.constitutions
    store[req.name] = {
        "name": req.name,
        "description": req.description or "",
        "principles": req.principles or [],
        "boundaries": req.boundaries or {},
    }
    return ConstitutionResponse(**store[req.name])


@router.get("/constitution/{name}", response_model=ConstitutionResponse)
async def get_constitution(name: str, request: Request):
    store = request.app.state.constitutions
    if name not in store:
        # Check built-in constitutions
        if name == "agent_safety_default":
            try:
                from frontier_ops.boundary.constitution import ConstitutionSpec
                spec = ConstitutionSpec.agent_safety_default()
                return ConstitutionResponse(
                    name="agent_safety_default",
                    description="Default agent safety constitution from frontier-ops",
                    principles=[str(p) for p in getattr(spec, "principles", [])],
                    boundaries={k: v for k, v in getattr(spec, "boundaries", {}).items()} if hasattr(spec, "boundaries") else {},
                )
            except Exception:
                pass
        raise HTTPException(status_code=404, detail=f"Constitution {name!r} not found")
    return ConstitutionResponse(**store[name])
