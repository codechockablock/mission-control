"""Authentication middleware for Mission Control server."""

from __future__ import annotations

import os
from typing import Optional

from fastapi import Request, HTTPException


API_KEY_HEADER = "X-Mission-Control-Key"
API_KEY_ENV = "MISSION_CONTROL_API_KEY"


def get_api_key() -> Optional[str]:
    """Get the configured API key from environment."""
    return os.environ.get(API_KEY_ENV)


async def check_auth(request: Request) -> None:
    """
    Validate API key if one is configured.

    If MISSION_CONTROL_API_KEY is not set, auth is skipped (dev mode).
    """
    expected = get_api_key()
    if expected is None:
        return

    provided = request.headers.get(API_KEY_HEADER)
    if provided != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
