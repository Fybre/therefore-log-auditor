"""Dashboard: findings queue, evidence view, known-activity display, verdict feedback, and
/admin/* config management (tenants/servers, per-tenant rule toggles, SMTP delivery, local
accounts) - all of which used to live in config/tenants.yaml and .env. See auth.py for the
local-account login model."""
from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import config as cfg
from .. import passwords
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
        auth.bootstrap_first_admin(conn)
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


def register_routes(app: FastAPI) -> None:
    templates: Jinja2Templates = app.state.templates

    def render(request, name, ctx, status_code: int = 200):
        return templates.TemplateResponse(request, name, {"user": auth.current_user(request), **ctx},
                                          status_code=status_code)

    # --- Auth --------------------------------------------------------------------------

    @app.get("/login")
    def login_form(request: Request, next: str = "/"):
        return render(request, "login.html", {"next": next, "error": None})

    @app.post("/login")
    def login_submit(request: Request, conn=Depends(db_conn), username: str = Form(...),
                      password: str = Form(...), next: str = Form("/")):
        user = auth.authenticate(conn, username, password)
        if not user:
            return render(request, "login.html", {"next": next, "error": "Invalid username or password"},
                          status_code=401)
        request.session["user"] = {"id": user.id, "username": user.username}
        return RedirectResponse(url=next or "/", status_code=303)

    @app.post("/logout")
    def logout(request: Request):
        request.session.clear()
        return RedirectResponse(url="/login", status_code=303)

    # --- Findings ------------------------------------------------------------------------

    @app.get("/")
    def tenants_index(request: Request, conn=Depends(db_conn)):
        rows = []
        with conn.cursor() as cur:
            for t in cfg.load_tenants(conn, include_disabled=True):
                cur.execute(
                    """SELECT count(*) FILTER (WHERE severity='high' AND status='open') AS high,
                              count(*) FILTER (WHERE severity='medium' AND status='open') AS medium,
                              count(*) FILTER (WHERE severity='low' AND status='open') AS low,
                              max(last_ts) AS last_finding
                       FROM findings WHERE tenant_id=%s""", (t.id,))
                rows.append({"tenant": t, **cur.fetchone()})
        return render(request, "tenants.html", {"rows": rows})

    @app.get("/t/{tenant_id}/findings")
    def findings_list(request: Request, tenant_id: str, conn=Depends(db_conn),
                       min_severity: str = "low", status: str = "", days: int = 30):
        tenant = cfg.get_tenant(conn, tenant_id)
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
        return render(request, "findings.html", {
            "tenant": tenant, "findings": findings, "min_severity": min_severity,
            "status": status, "days": days, "statuses": REVIEW_STATUSES})

    @app.get("/t/{tenant_id}/findings/{finding_id}")
    def finding_detail(request: Request, tenant_id: str, finding_id: int, conn=Depends(db_conn)):
        tenant = cfg.get_tenant(conn, tenant_id)
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM findings WHERE tenant_id=%s AND id=%s", (tenant_id, finding_id))
            finding = cur.fetchone()
            if not finding:
                return render(request, "not_found.html", {"tenant": tenant}, status_code=404)
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
        return render(request, "finding_detail.html", {
            "tenant": tenant, "f": finding, "evidence": evidence, "incident": incident,
            "statuses": REVIEW_STATUSES})

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

    @app.post("/t/{tenant_id}/findings/bulk-review")
    async def bulk_review_findings(request: Request, tenant_id: str, conn=Depends(db_conn)):
        form = await request.form()
        ids = [int(i) for i in form.getlist("ids") if str(i).isdigit()]
        status = form.get("status", "")
        note = (form.get("note", "") or "").strip() or None
        return_qs = form.get("return_qs", "")
        if ids and status in REVIEW_STATUSES:
            user = auth.current_user(request)
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE findings SET status=%s, reviewed_by=%s, reviewed_note=%s, reviewed_at=now()
                       WHERE tenant_id=%s AND id = ANY(%s)""",
                    (status, user.username if user else None, note, tenant_id, ids))
            conn.commit()
        url = f"/t/{tenant_id}/findings" + (f"?{return_qs}" if return_qs else "")
        return RedirectResponse(url=url, status_code=303)

    @app.get("/t/{tenant_id}/known")
    def known_activity(request: Request, tenant_id: str, conn=Depends(db_conn)):
        tenant = cfg.get_tenant(conn, tenant_id)
        if not tenant:
            return render(request, "not_found.html", {"tenant": None}, status_code=404)
        return render(request, "known.html", {"tenant": tenant, "known": tenant.known or {}, "saved": False})

    @app.post("/t/{tenant_id}/known")
    def known_activity_save(request: Request, tenant_id: str, conn=Depends(db_conn),
                             users: str = Form(""), ips: str = Form(""),
                             windows: str = Form(""), notes: str = Form("")):
        tenant = cfg.get_tenant(conn, tenant_id)
        if not tenant:
            return render(request, "not_found.html", {"tenant": None}, status_code=404)
        known = {"users": _split_lines(users), "ips": _split_lines(ips),
                "windows": _parse_windows(windows), "notes": _split_lines(notes)}
        cfg.save_tenant(conn, id=tenant_id, base_url=tenant.base_url, username=tenant.username,
                        password=None, tenant_name_override=tenant.tenant_name_override,
                        log_category_no=tenant.log_category_no, log_tz=tenant.log_tz,
                        display_tz=tenant.display_tz, schedule_cron=tenant.schedule.get("daily", "30 3 * * *"),
                        llm_enabled=tenant.llm.get("enabled", True), llm_redact=tenant.llm.get("redact", True),
                        digest_email_to=tenant.digest.get("email_to", []), known=known, enabled=tenant.enabled)
        return render(request, "known.html", {"tenant": cfg.get_tenant(conn, tenant_id),
                                              "known": known, "saved": True})

    # --- Admin: tenants/servers ------------------------------------------------------------

    @app.get("/admin/tenants")
    def admin_tenants(request: Request, conn=Depends(db_conn)):
        tenants = cfg.load_tenants(conn, include_disabled=True)
        return render(request, "admin_tenants.html", {"tenants": tenants})

    @app.get("/admin/tenants/new")
    def admin_tenant_new_form(request: Request):
        return render(request, "admin_tenant_form.html", {"t": None, "row": None, "error": None})

    @app.get("/admin/tenants/{tenant_id}/edit")
    def admin_tenant_edit_form(request: Request, tenant_id: str, conn=Depends(db_conn)):
        row = cfg.get_tenant_row(conn, tenant_id)
        if not row:
            return render(request, "not_found.html", {"tenant": None}, status_code=404)
        return render(request, "admin_tenant_form.html", {"t": tenant_id, "row": row, "error": None})

    @app.post("/admin/tenants/test-connection")
    async def admin_tenant_test_connection(request: Request):
        from ..therefore import ThereforeClient
        form = await request.form()
        test_tenant = _test_tenant_from_form(form)
        try:
            ThereforeClient(test_tenant, timeout=15).test_connection()
            note = f" (TenantName header: {test_tenant.tenant_name})" if test_tenant.tenant_name else ""
            test_result = {"ok": True, "message": f"Connected successfully.{note}"}
        except Exception as exc:
            test_result = {"ok": False, "message": str(exc)}
        return render(request, "admin_tenant_form.html", {
            "t": form.get("tenant_id") or None, "row": _row_from_form(form), "error": None,
            "test_result": test_result, "new_id": form.get("id")})

    @app.post("/admin/tenants/detect-category")
    async def admin_tenant_detect_category(request: Request):
        from ..therefore import ThereforeClient
        form = await request.form()
        test_tenant = _test_tenant_from_form(form)
        category_matches: list[dict] = []
        detected: int | None = None
        try:
            cats = ThereforeClient(test_tenant, timeout=20).list_categories()
            matches = [c for c in cats if "logfile" in (c["Name"] or "").lower()]
            if len(matches) == 1:
                detected = matches[0]["CategoryNo"]
                test_result = {"ok": True,
                               "message": f"Detected: category {detected} (\"{matches[0]['Name']}\")."}
            elif matches:
                category_matches = matches
                test_result = {"ok": True,
                               "message": f"Found {len(matches)} categories with \"Logfiles\" in "
                                          "the name - pick the right one below."}
            else:
                category_matches = cats
                test_result = {"ok": False,
                               "message": f"No category named \"Logfiles\" found among "
                                          f"{len(cats)} categories - pick one below, or check "
                                          "this tenant's Solution Designer for the right name."}
        except Exception as exc:
            test_result = {"ok": False, "message": str(exc)}

        row = _row_from_form(form)
        if detected is not None:
            row["log_category_no"] = detected
        return render(request, "admin_tenant_form.html", {
            "t": form.get("tenant_id") or None, "row": row, "error": None,
            "test_result": test_result, "new_id": form.get("id"),
            "category_matches": category_matches})

    @app.post("/admin/tenants/new")
    def admin_tenant_create(request: Request, conn=Depends(db_conn),
                             id: str = Form(...), base_url: str = Form(...),
                             username: str = Form(""), password: str = Form(""),
                             tenant_name_override: str = Form(""), log_category_no: int = Form(1),
                             log_tz: str = Form("UTC"), display_tz: str = Form("UTC"),
                             schedule_cron: str = Form("30 3 * * *"),
                             llm_enabled: bool = Form(False), llm_redact: bool = Form(False),
                             digest_email_to: str = Form(""), enabled: bool = Form(False)):
        if cfg.get_tenant_row(conn, id):
            return render(request, "admin_tenant_form.html",
                          {"t": None, "row": None, "error": f"Tenant '{id}' already exists"}, status_code=400)
        cfg.save_tenant(conn, id=id, base_url=base_url, username=username, password=password,
                        tenant_name_override=tenant_name_override or None,
                        log_category_no=log_category_no, log_tz=log_tz, display_tz=display_tz,
                        schedule_cron=schedule_cron, llm_enabled=llm_enabled, llm_redact=llm_redact,
                        digest_email_to=_split_emails(digest_email_to), known={}, enabled=enabled)
        return RedirectResponse(url="/admin/tenants", status_code=303)

    @app.post("/admin/tenants/{tenant_id}/edit")
    def admin_tenant_update(request: Request, tenant_id: str, conn=Depends(db_conn),
                             base_url: str = Form(...), username: str = Form(""),
                             password: str = Form(""), tenant_name_override: str = Form(""),
                             log_category_no: int = Form(1), log_tz: str = Form("UTC"),
                             display_tz: str = Form("UTC"), schedule_cron: str = Form("30 3 * * *"),
                             llm_enabled: bool = Form(False), llm_redact: bool = Form(False),
                             digest_email_to: str = Form(""), enabled: bool = Form(False)):
        existing = cfg.get_tenant(conn, tenant_id)
        cfg.save_tenant(conn, id=tenant_id, base_url=base_url, username=username,
                        password=(password or None), tenant_name_override=tenant_name_override or None,
                        log_category_no=log_category_no, log_tz=log_tz, display_tz=display_tz,
                        schedule_cron=schedule_cron, llm_enabled=llm_enabled, llm_redact=llm_redact,
                        digest_email_to=_split_emails(digest_email_to),
                        known=(existing.known if existing else {}), enabled=enabled)
        return RedirectResponse(url="/admin/tenants", status_code=303)

    @app.post("/admin/tenants/{tenant_id}/delete")
    def admin_tenant_delete(request: Request, tenant_id: str, conn=Depends(db_conn),
                             confirm: str = Form("")):
        if confirm == tenant_id:
            cfg.delete_tenant(conn, tenant_id)
        return RedirectResponse(url="/admin/tenants", status_code=303)

    @app.post("/admin/tenants/{tenant_id}/run")
    def admin_tenant_run(request: Request, tenant_id: str, conn=Depends(db_conn)):
        """Run collect -> rules -> triage -> digest right now, outside its cron schedule."""
        from ..pipeline import run_tenant
        tenant = cfg.get_tenant(conn, tenant_id)
        if not tenant:
            return render(request, "not_found.html", {"tenant": None}, status_code=404)
        stats = run_tenant(request.app.state.settings, tenant)
        return render(request, "admin_tenant_run_result.html", {"tenant_id": tenant_id, "stats": stats})

    @app.get("/admin/tenants/{tenant_id}/rules")
    def admin_tenant_rules(request: Request, tenant_id: str, conn=Depends(db_conn)):
        from ..rules import builtin  # noqa: F401  (registers rules)
        from ..rules.engine import RULES
        settings: Settings = request.app.state.settings
        overrides = cfg.rule_settings_for(conn, tenant_id)
        rows = []
        for rule_id in sorted(RULES):
            global_default = bool(settings.rules.get(rule_id, {}).get("enabled", True))
            ov = overrides.get(rule_id, {})
            rows.append({"rule_id": rule_id, "global_default": global_default,
                        "enabled": ov.get("enabled"), "config": ov.get("config") or {}})
        return render(request, "admin_tenant_rules.html", {"tenant_id": tenant_id, "rows": rows})

    @app.post("/admin/tenants/{tenant_id}/rules")
    async def admin_tenant_rules_save(request: Request, tenant_id: str, conn=Depends(db_conn)):
        from ..rules import builtin  # noqa: F401
        from ..rules.engine import RULES
        form = await request.form()
        for rule_id in RULES:
            choice = form.get(f"enabled__{rule_id}", "inherit")
            enabled = {"inherit": None, "on": True, "off": False}.get(choice)
            raw_config = (form.get(f"config__{rule_id}", "") or "").strip()
            config_obj = {}
            if raw_config:
                import json
                try:
                    config_obj = json.loads(raw_config)
                except ValueError:
                    continue   # ignore unparsable JSON rather than 500 the whole save
            cfg.set_rule_setting(conn, tenant_id, rule_id, enabled, config_obj)
        return RedirectResponse(url=f"/admin/tenants/{tenant_id}/rules", status_code=303)

    # --- Admin: SMTP -------------------------------------------------------------------

    @app.get("/admin/smtp")
    def admin_smtp_form(request: Request, conn=Depends(db_conn)):
        smtp = cfg.load_smtp(conn) or {"host": "", "port": 587, "user": "", "from": "", "starttls": True}
        return render(request, "admin_smtp.html", {"smtp": smtp, "saved": False})

    @app.post("/admin/smtp")
    def admin_smtp_save(request: Request, conn=Depends(db_conn), host: str = Form(""),
                         port: int = Form(587), user: str = Form(""), password: str = Form(""),
                         from_addr: str = Form(""), starttls: bool = Form(False)):
        cfg.save_smtp(conn, host=host, port=port, user=user, password=(password or None),
                      from_addr=from_addr, starttls=starttls)
        smtp = cfg.load_smtp(conn)
        return render(request, "admin_smtp.html", {"smtp": smtp, "saved": True})

    # --- Admin: local accounts -----------------------------------------------------------

    @app.get("/admin/users")
    def admin_users(request: Request, conn=Depends(db_conn)):
        with conn.cursor() as cur:
            cur.execute("SELECT id, username, disabled, created_at FROM web_users ORDER BY username")
            users = cur.fetchall()
        return render(request, "admin_users.html", {"users": users, "error": None})

    @app.post("/admin/users/new")
    def admin_user_create(request: Request, conn=Depends(db_conn), username: str = Form(...),
                           password: str = Form(...)):
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM web_users WHERE username=%s", (username,))
            if cur.fetchone():
                cur.execute("SELECT id, username, disabled, created_at FROM web_users ORDER BY username")
                return render(request, "admin_users.html",
                              {"users": cur.fetchall(), "error": f"'{username}' already exists"},
                              status_code=400)
            cur.execute("INSERT INTO web_users (username, password_hash) VALUES (%s, %s)",
                        (username, passwords.hash_password(password)))
        conn.commit()
        return RedirectResponse(url="/admin/users", status_code=303)

    @app.post("/admin/users/{user_id}/toggle")
    def admin_user_toggle(request: Request, user_id: int, conn=Depends(db_conn)):
        with conn.cursor() as cur:
            cur.execute("UPDATE web_users SET disabled = NOT disabled WHERE id=%s", (user_id,))
        conn.commit()
        return RedirectResponse(url="/admin/users", status_code=303)

    @app.post("/admin/users/{user_id}/password")
    def admin_user_password(request: Request, user_id: int, conn=Depends(db_conn),
                             password: str = Form(...)):
        with conn.cursor() as cur:
            cur.execute("UPDATE web_users SET password_hash=%s WHERE id=%s",
                        (passwords.hash_password(password), user_id))
        conn.commit()
        return RedirectResponse(url="/admin/users", status_code=303)


def _test_tenant_from_form(form) -> cfg.Tenant:
    """A throwaway, unsaved Tenant built from an add/edit-tenant form submission, for
    test-connection and detect-category (both need a real client but nothing persisted)."""
    return cfg.Tenant(id="_test", base_url=form.get("base_url", ""), username=form.get("username", ""),
                      password=form.get("password", ""),
                      tenant_name_override=form.get("tenant_name_override") or None)


def _row_from_form(form) -> dict:
    """Reconstructs the admin_tenant_form.html 'row' dict from a submitted form, so
    test-connection/detect-category can re-render the form with what was typed, unsaved."""
    def get(name, default=""):
        return form.get(name, default)
    return {
        "base_url": get("base_url"), "therefore_username": get("username"),
        "password": get("password"),   # echoed back so a successful test doesn't need retyping
        "tenant_name_override": get("tenant_name_override"),
        "log_category_no": int(get("log_category_no") or 1), "log_tz": get("log_tz", "UTC"),
        "display_tz": get("display_tz", "UTC"), "schedule_cron": get("schedule_cron", "30 3 * * *"),
        "llm_enabled": bool(get("llm_enabled")), "llm_redact": bool(get("llm_redact")),
        "digest_email_to": _split_emails(get("digest_email_to")), "enabled": bool(get("enabled")),
    }


def _split_emails(raw: str) -> list[str]:
    return [e.strip() for e in raw.replace(",", "\n").splitlines() if e.strip()]


def _split_lines(raw: str) -> list[str]:
    return [line.strip() for line in raw.splitlines() if line.strip()]


_WINDOW_RE = re.compile(r"^(?P<start>.+?)\s+to\s+(?P<end>.+):\s*(?P<note>.*)$")


def _parse_windows(raw: str) -> list[dict]:
    """One window per line: '<start> to <end>: <note>' - same format the digest/known page
    already display them in, so what you see is what you type back in."""
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _WINDOW_RE.match(line)
        if m:
            out.append({"start": m.group("start").strip(), "end": m.group("end").strip(),
                       "note": m.group("note").strip()})
    return out
