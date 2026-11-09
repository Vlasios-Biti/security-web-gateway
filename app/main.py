from fastapi import FastAPI, Request
import time
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.trustedhost import TrustedHostMiddleware
from app import auth
from app.db import verify_schema
from app.config import MANAGEMENT_FQDN, PROXY_IP, APP_VERSION, MODE, APP_ROOT
from app.routers import (
    auth_routes, overview, domains, ips, system_rules, traffic, policies,
    deployments, audit, users, system, bulk, api, applications, groups, intelligence, connection
)

verify_schema()
app = FastAPI(title="Security Web Gateway Manager", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=[MANAGEMENT_FQDN, PROXY_IP, "127.0.0.1", "localhost"],
)
templates = Jinja2Templates(directory=str(APP_ROOT / "templates"))
app.state.templates = templates
app.state.mode = MODE
app.state.version = APP_VERSION
app.mount("/static", StaticFiles(directory=str(APP_ROOT / "static")), name="static")


@app.middleware("http")
async def gate(request: Request, call_next):
    # Measure the complete management request, including session lookup.  This makes
    # login/session regressions visible in Server-Timing instead of hiding them.
    started = time.perf_counter()
    public = request.url.path in ("/login", "/healthz") or request.url.path.startswith("/static/")
    request.state.user = auth.user_from_request(request)
    if not public and not request.state.user:
        response = RedirectResponse("/login", 303)
    else:
        response = await call_next(request)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    response.headers["Server-Timing"] = f"app;dur={elapsed_ms:.1f}"
    response.headers["X-Response-Time-Ms"] = f"{elapsed_ms:.1f}"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    )
    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=300"
    else:
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/healthz")
def healthz():
    return JSONResponse({"status": "ok", "service": "security-web-gateway-manager", "version": APP_VERSION, "mode": MODE})


for r in (
    auth_routes.router, overview.router, domains.router, ips.router, system_rules.router,
    traffic.router, policies.router, deployments.router, audit.router, users.router,
    system.router, bulk.router, api.router, applications.router, groups.router, intelligence.router, connection.router,
):
    app.include_router(r)
