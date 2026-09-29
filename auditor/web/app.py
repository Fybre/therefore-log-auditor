"""Dashboard: findings queue, evidence view, known-activity display, verdict feedback.
Read-mostly over the same Postgres the pipeline writes to - no write path here touches
the Therefore API. See auth.py for how login is meant to be swapped for Entra ID later."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..config import Settings, load_settings
from ..db import connect, migrate
from . import auth

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"
REVIEW_STATUSES = ["open", "acknowledged", "resolved", "false_positive"]
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def local_time(ts: dt.datetime | None, tz: str) -> str:
    if not ts:
        return "-"
    return ts.astimezone(ZoneInfo(tz)).strftime("%d %b %Y %H:%M")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    with connect(settings.database_url) as conn:
        migrate(conn)
    app = FastAPI(title="Therefore Log Auditor")
    app.state.settings = settings

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    templates.env.filters["local_time"] = local_time
    app.state.templates = templates

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    # Order matters: SessionMiddleware must run before RequireLoginMiddleware, and Starlette
    # runs the LAST-added middleware first, so RequireLoginMiddleware is added first here.
    app.add_middleware(auth.RequireLoginMiddleware)
    from starlette.middleware.sessions import SessionMiddleware
    app.add_middleware(SessionMiddleware, secret_key=auth.session_secret(), same_site="lax")

    register_routes(app)
    return app


def db_conn(request: Request):
    conn = connect(request.app.state.settings.database_url)
    try:
        yield conn
    finally:
        conn.close()


def get_tenant(request: Request, tenant_id: str):
    return request.app.state.settings.tenant(tenant_id)


def register_routes(app: FastAPI) -> None:
    templates: Jinja2Templates = app.state.templates

    @app.get("/login")
    def login_form(request: Request, next: str = "/"):
        return templates.TemplateResponse(request, "login.html", {"next": next, "error": None})

    @app.post("/login")
    def login_submit(request: Request, username: str = Form(...), password: str = Form(...),
                      next: str = Form("/")):
        user = auth.authenticate(username, password)
        if not user:
            return templates.TemplateResponse(
                request, "login.html", {"next": next, "error": "Invalid username or password"},
                status_code=401)
        request.session["user"] = user.username
        return RedirectResponse(url=next or "/", status_code=303)

    @app.post("/logout")
    def logout(request: Request):
        request.session.clear()
        return RedirectResponse(url="/login", status_code=303)

    @app.get("/")
    def tenants_index(request: Request, conn=Depends(db_conn)):
        settings: Settings = request.app.state.settings
        rows = []
        with conn.cursor() as cur:
            for t in settings.tenants:
                cur.execute(
                    """SELECT count(*) FILTER (WHERE severity='high' AND status='open') AS high,
                              count(*) FILTER (WHERE severity='medium' AND status='open') AS medium,
                              count(*) FILTER (WHERE severity='low' AND status='open') AS low,
                              max(last_ts) AS last_finding
                       FROM findings WHERE tenant_id=%s""", (t.id,))
                rows.append({"tenant": t, **cur.fetchone()})
        return templates.TemplateResponse(request, "tenants.html", {"rows": rows,
                                          "user": auth.current_user(request)})

    @app.get("/t/{tenant_id}/findings")
    def findings_list(request: Request, tenant_id: str, conn=Depends(db_conn),
                       min_severity: str = "low", status: str = "", days: int = 30):
        tenant = get_tenant(request, tenant_id)
        allowed = list(SEV_ORDER)[:list(SEV_ORDER).index(min_severity) + 1] if min_severity in SEV_ORDER else list(SEV_ORDER)
        since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
        with conn.cursor() as cur:
            cur.execute(
                """SELECT id, rule_id, title, severity, status, last_ts, llm_verdict,
                          incident_key, suppressed_by,
                          count(*) OVER (PARTITION BY COALESCE(incident_key, 'solo:' || id::text))
                              AS incident_size
                   FROM findings
                   WHERE tenant_id=%s AND severity = ANY(%s) AND last_ts >= %s
                         AND (%s = '' OR status = %s)
                   ORDER BY array_position(ARRAY['high','medium','low','info'], severity), last_ts DESC
                   LIMIT 300""",
                (tenant_id, allowed, since, status, status))
            findings = cur.fetchall()
        return templates.TemplateResponse(request, "findings.html", {
            "tenant": tenant, "findings": findings, "min_severity": min_severity,
            "status": status, "days": days, "statuses": REVIEW_STATUSES,
            "user": auth.current_user(request)})

    @app.get("/t/{tenant_id}/findings/{finding_id}")
    def finding_detail(request: Request, tenant_id: str, finding_id: int, conn=Depends(db_conn)):
        tenant = get_tenant(request, tenant_id)
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM findings WHERE tenant_id=%s AND id=%s", (tenant_id, finding_id))
            finding = cur.fetchone()
            if not finding:
                return templates.TemplateResponse(request, "not_found.html", {"tenant": tenant},
                                                   status_code=404)
            evidence = []
            if finding["evidence_ids"]:
                cur.execute(
                    """SELECT ts, username, host, ip, action, result_code, obj_doc_no, category,
                              client, message
                       FROM events WHERE tenant_id=%s AND id = ANY(%s) ORDER BY ts LIMIT 200""",
                    (tenant_id, finding["evidence_ids"]))
                evidence = cur.fetchall()
            incident = []
            if finding["incident_key"]:
                cur.execute(
                    """SELECT id, title, severity, rule_id FROM findings
                       WHERE tenant_id=%s AND incident_key=%s AND id <> %s""",
                    (tenant_id, finding["incident_key"], finding_id))
                incident = cur.fetchall()
        return templates.TemplateResponse(request, "finding_detail.html", {
            "tenant": tenant, "f": finding, "evidence": evidence, "incident": incident,
            "statuses": REVIEW_STATUSES, "user": auth.current_user(request)})

    @app.post("/t/{tenant_id}/findings/{finding_id}/review")
    def review_finding(request: Request, tenant_id: str, finding_id: int, conn=Depends(db_conn),
                        status: str = Form(...), note: str = Form("")):
        user = auth.current_user(request)
        status = status if status in REVIEW_STATUSES else "open"
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE findings SET status=%s, reviewed_by=%s, reviewed_note=%s, reviewed_at=now()
                   WHERE tenant_id=%s AND id=%s""",
                (status, user.username if user else None, note or None, tenant_id, finding_id))
        conn.commit()
        return RedirectResponse(url=f"/t/{tenant_id}/findings/{finding_id}", status_code=303)

    @app.get("/t/{tenant_id}/known")
    def known_activity(request: Request, tenant_id: str):
        tenant = get_tenant(request, tenant_id)
        return templates.TemplateResponse(request, "known.html", {
            "tenant": tenant, "known": tenant.known or {}, "user": auth.current_user(request)})
