"""Dashboard application — serves static files."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse

STATIC_DIR = Path(__file__).parent / "static"


def create_dashboard_app(api_url: str = "http://localhost:8420") -> FastAPI:
    """Create a FastAPI app that serves the dashboard static files."""
    app = FastAPI(title="Mission Control Dashboard")

    @app.get("/")
    async def index():
        html_path = STATIC_DIR / "index.html"
        content = html_path.read_text()
        # Inject API URL
        content = content.replace("{{API_URL}}", api_url)
        return HTMLResponse(content)

    @app.get("/app.js")
    async def app_js():
        js_path = STATIC_DIR / "app.js"
        content = js_path.read_text()
        content = content.replace("{{API_URL}}", api_url)
        from fastapi.responses import Response
        return Response(content=content, media_type="application/javascript")

    @app.get("/style.css")
    async def style_css():
        css_path = STATIC_DIR / "style.css"
        from fastapi.responses import Response
        return Response(content=css_path.read_text(), media_type="text/css")

    return app
