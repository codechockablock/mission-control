"""Audit verification endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel

router = APIRouter()


class VerifyRequest(BaseModel):
    session_id: Optional[str] = None


class VerifyResponse(BaseModel):
    valid: bool
    chain_length: int
    head_hash: str
    message: str


@router.post("/audit/verify", response_model=VerifyResponse)
async def verify_audit(req: VerifyRequest, request: Request):
    mc = request.app.state.mc

    if mc.recorder is None:
        return VerifyResponse(
            valid=True,
            chain_length=0,
            head_hash="",
            message="No flight recorder configured",
        )

    try:
        valid = mc.recorder.verify_chain()
        chain = mc.recorder.chain
        head = chain.head() if chain else None
        return VerifyResponse(
            valid=valid,
            chain_length=head.seq + 1 if head else 0,
            head_hash=head.chain_hash[:12] if head and head.chain_hash else "",
            message="Chain integrity verified" if valid else "Chain integrity FAILED",
        )
    except Exception as e:
        return VerifyResponse(
            valid=False,
            chain_length=0,
            head_hash="",
            message=f"Verification error: {e}",
        )
