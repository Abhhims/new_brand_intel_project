"""FastAPI application — REST API for the analyst dashboard (FND-08). OpenAPI docs at /docs."""

import time
import uuid

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api import alerts, auth, brands, correlation, emails, exports, findings, integrations, scans, settings, stats
from app.config import get_settings
from app.db.session import engine
from app.logging import configure_logging

configure_logging()
log = structlog.get_logger("api")

DESCRIPTION = """
REST API of the **Beyond Cloud Brand Intelligence Automation Platform**.

Authenticate with `POST /api/v1/auth/login`, then send `Authorization: Bearer <token>`.
Requirement IDs (e.g. DSH-07) refer to `docs/requirements/01-requirements-register.md`.
"""

app = FastAPI(title="Beyond Cloud Brand Intelligence API", version="1.0.0", description=DESCRIPTION,
              docs_url="/docs", redoc_url="/redoc", openapi_url="/openapi.json")

app.add_middleware(
    CORSMiddleware, allow_origins=get_settings().cors_origins, allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"], expose_headers=["Content-Disposition"],
)


@app.middleware("http")
async def request_log(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
    structlog.contextvars.bind_contextvars(request_id=request_id)
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        log.exception("unhandled_error", path=request.url.path)
        response = JSONResponse({"detail": "Internal server error", "request_id": request_id}, status_code=500)
    response.headers["x-request-id"] = request_id
    log.info("request", method=request.method, path=request.url.path, status=response.status_code,
             ms=round((time.perf_counter() - started) * 1000, 1))
    structlog.contextvars.clear_contextvars()
    return response


for r in (auth.router, brands.router, alerts.router, findings.router, correlation.router, settings.router,
          emails.router, scans.router, stats.router, exports.router, integrations.router):
    app.include_router(r, prefix="/api/v1")


@app.get("/health", tags=["ops"])
def health():
    checks = {"database": "ok"}
    try:
        with engine.connect() as conn:
            conn.execute(text("select 1"))
    except Exception as exc:  # noqa: BLE001
        checks["database"] = f"error: {exc.__class__.__name__}"
    ok = all(v == "ok" for v in checks.values())
    return JSONResponse({"status": "ok" if ok else "degraded", **checks}, status_code=200 if ok else 503)
