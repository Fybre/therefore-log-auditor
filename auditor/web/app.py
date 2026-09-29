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


def humanize_schedule(cron: str) -> str:
    """"30 3 * * *" -> "03:30 daily"; anything not a plain daily pattern is shown as-is."""
    m = _DAILY_CRON_RE.match(cron or "")
    if m:
        return f"{int(m.group(2)):02d}:{int(m.group(1)):02d} daily"
    return cron


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    with connect(settings.database_url) as conn:
        migrate(conn)
        auth.bootstrap_first_admin(conn)
        cfg.refresh_from_db(settings, conn)   # SMTP is DB-config; don't start out with empty defaults
    app = FastAPI(title="Therefore Log Auditor")
    app.state.settings = settings

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    templates.env.filters["local_time"] = local_time
    templates.env.filters["humanize_schedule"] = humanize_schedule
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


def _save_known(conn, tenant: cfg.Tenant, known: dict) -> None:
    cfg.save_tenant(conn, id=tenant.id, base_url=tenant.base_url, username=tenant.username,
                    password=None, tenant_name_override=tenant.tenant_name_override,
                    log_category_no=tenant.log_category_no, log_tz=tenant.log_tz,
                    display_tz=tenant.display_tz, schedule_cron=tenant.schedule.get("daily", "30 3 * * *"),
                    llm_enabled=tenant.llm.get("enabled", True), llm_redact=tenant.llm.get("redact", True),
                    digest_email_to=tenant.digest.get("email_to", []),
                    digest_only_on_new=tenant.digest.get("only_on_new", False),
                    known=known, enabled=tenant.enabled)


def _reapply_suppression(conn, tenant_id: str, tenant: cfg.Tenant) -> int:
    """After a known.* change, immediately downgrade any currently-open finding that now
    matches - rather than waiting for the next scheduled run - so a quick action's effect is
    visible right away. Returns how many findings were touched."""
    from ..rules.engine import Finding, suppression_for
    touched = 0
    with conn.cursor() as cur:
        cur.execute("""SELECT id, rule_id, subject_users, subject_ips, details, first_ts, last_ts
                       FROM findings WHERE tenant_id=%s AND severity <> 'info'""", (tenant_id,))
        rows = cur.fetchall()
        for r in rows:
            f = Finding(rule_id=r["rule_id"], dedupe_key="", title="", severity="low",
                        first_ts=r["first_ts"], last_ts=r["last_ts"], details=r["details"] or {},
                        subject_users=r["subject_users"] or [], subject_ips=r["subject_ips"] or [])
            supp = suppression_for(f, tenant)
            if supp:
                cur.execute("UPDATE findings SET severity='info', suppressed_by=%s WHERE id=%s",
                            (supp, r["id"]))
                touched += 1
    conn.commit()
    return touched


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
                       min_severity: str = "low", status: str = "", days: int = 30, rule: str = ""):
        tenant = cfg.get_tenant(conn, tenant_id)
        allowed = list(SEV_ORDER)[:list(SEV_ORDER).index(min_severity) + 1] if min_severity in SEV_ORDER else list(SEV_ORDER)
        since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
        with conn.cursor() as cur:
            # Severity breakdown ignores the severity filter itself, so switching min_severity
            # doesn't hide the very counts that would tell you whether to switch it.
            cur.execute("""SELECT severity, count(*) AS n FROM findings
                           WHERE tenant_id=%s AND last_ts >= %s AND (%s = '' OR status = %s)
                           GROUP BY 1""", (tenant_id, since, status, status))
            severity_counts = {r["severity"]: r["n"] for r in cur.fetchall()}
            cur.execute("""SELECT rule_id, count(*) AS n FROM findings
                           WHERE tenant_id=%s AND severity = ANY(%s) AND last_ts >= %s
                                 AND (%s = '' OR status = %s)
                           GROUP BY 1 ORDER BY 2 DESC""", (tenant_id, allowed, since, status, status))
            rule_counts = cur.fetchall()
            cur.execute(
                """SELECT id, rule_id, title, severity, status, last_ts, llm_verdict,
                          incident_key, suppressed_by,
                          count(*) OVER (PARTITION BY COALESCE(incident_key, 'solo:' || id::text))
                              AS incident_size
                   FROM findings
                   WHERE tenant_id=%s AND severity = ANY(%s) AND last_ts >= %s
                         AND (%s = '' OR status = %s) AND (%s = '' OR rule_id = %s)
                   ORDER BY array_position(ARRAY['high','medium','low','info'], severity), last_ts DESC
                   LIMIT 300""",
                (tenant_id, allowed, since, status, status, rule, rule))
            findings = cur.fetchall()
        return render(request, "findings.html", {
            "tenant": tenant, "items": _group_for_display(findings, tenant.display_tz),
            "min_severity": min_severity, "status": status, "days": days, "rule": rule,
            "statuses": REVIEW_STATUSES, "severity_counts": severity_counts, "rule_counts": rule_counts,
            "total": sum(severity_counts.values())})

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

    @app.post("/t/{tenant_id}/findings/{finding_id}/suppress")
    def suppress_from_finding(request: Request, tenant_id: str, finding_id: int, conn=Depends(db_conn),
                               action: str = Form(...)):
        """Quick actions right from a finding: mark its user/IP as known, or mute its whole
        category - the same known.* mechanism as the Known Activity page, just filled in from
        this finding instead of retyping the value there."""
        tenant = cfg.get_tenant(conn, tenant_id)
        if not tenant:
            return render(request, "not_found.html", {"tenant": None}, status_code=404)
        with conn.cursor() as cur:
            cur.execute("SELECT subject_users, subject_ips, rule_id, details FROM findings "
                       "WHERE tenant_id=%s AND id=%s", (tenant_id, finding_id))
            f = cur.fetchone()
        if not f:
            return render(request, "not_found.html", {"tenant": tenant}, status_code=404)
        known = dict(tenant.known or {})
        if action == "know_user" and f["subject_users"]:
            users = set(known.get("users", []) or [])
            users.update(u.lower() for u in f["subject_users"])
            known["users"] = sorted(users)
        elif action == "know_ip" and f["subject_ips"]:
            ips = set(known.get("ips", []) or [])
            ips.update(f["subject_ips"])
            known["ips"] = sorted(ips)
        elif action == "mute_kind" and (f["details"] or {}).get("kind"):
            key = f"{f['rule_id']}:{f['details']['kind']}"
            muted = set(known.get("muted_kinds", []) or [])
            muted.add(key)
            known["muted_kinds"] = sorted(muted)
        else:
            return RedirectResponse(url=f"/t/{tenant_id}/findings/{finding_id}", status_code=303)
        _save_known(conn, tenant, known)
        _reapply_suppression(conn, tenant_id, cfg.get_tenant(conn, tenant_id))
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

    def _known_counts(conn, tenant_id: str, known: dict) -> dict:
        """How many current findings each known entry is responsible for suppressing - so a
        stale entry (0 findings) is visible next to a load-bearing one (dozens)."""
        counts: dict = {"users": {}, "ips": {}, "muted_kinds": {}}
        with conn.cursor() as cur:
            for u in known.get("users", []) or []:
                cur.execute("SELECT count(*) AS n FROM findings WHERE tenant_id=%s AND %s = ANY(subject_users)",
                            (tenant_id, u.lower()))
                counts["users"][u] = cur.fetchone()["n"]
            for ip in known.get("ips", []) or []:
                cur.execute("SELECT count(*) AS n FROM findings WHERE tenant_id=%s AND %s = ANY(subject_ips)",
                            (tenant_id, ip))
                counts["ips"][ip] = cur.fetchone()["n"]
            for key in known.get("muted_kinds", []) or []:
                rule_id, _, kind = key.partition(":")
                cur.execute("SELECT count(*) AS n FROM findings WHERE tenant_id=%s AND rule_id=%s "
                           "AND details->>'kind'=%s", (tenant_id, rule_id, kind))
                counts["muted_kinds"][key] = cur.fetchone()["n"]
        return counts

    @app.get("/t/{tenant_id}/known")
    def known_activity(request: Request, tenant_id: str, conn=Depends(db_conn)):
        from ..rules.settings_schema import MUTABLE_KINDS
        tenant = cfg.get_tenant(conn, tenant_id)
        if not tenant:
            return render(request, "not_found.html", {"tenant": None}, status_code=404)
        known = tenant.known or {}
        return render(request, "known.html", {
            "tenant": tenant, "known": known, "saved": False, "mutable_kinds": MUTABLE_KINDS,
            "counts": _known_counts(conn, tenant_id, known)})

    @app.post("/t/{tenant_id}/known")
    async def known_activity_save(request: Request, tenant_id: str, conn=Depends(db_conn)):
        from ..rules.settings_schema import MUTABLE_KINDS
        form = await request.form()
        tenant = cfg.get_tenant(conn, tenant_id)
        if not tenant:
            return render(request, "not_found.html", {"tenant": None}, status_code=404)
        muted = [key for key, _, _ in MUTABLE_KINDS if form.get(f"mute__{key}")]
        known = dict(tenant.known or {})
        known.update({"windows": _parse_windows(form.get("windows", "")),
                      "notes": _split_lines(form.get("notes", "")), "muted_kinds": muted})
        _save_known(conn, tenant, known)
        _reapply_suppression(conn, tenant_id, cfg.get_tenant(conn, tenant_id))
        return render(request, "known.html", {
            "tenant": cfg.get_tenant(conn, tenant_id), "known": known, "saved": True,
            "mutable_kinds": MUTABLE_KINDS, "counts": _known_counts(conn, tenant_id, known)})

    @app.post("/t/{tenant_id}/known/add")
    def known_add(request: Request, tenant_id: str, conn=Depends(db_conn),
                  kind: str = Form(...), value: str = Form(...)):
        tenant = cfg.get_tenant(conn, tenant_id)
        if not tenant or kind not in ("users", "ips") or not value.strip():
            return RedirectResponse(url=f"/t/{tenant_id}/known", status_code=303)
        known = dict(tenant.known or {})
        value = value.strip().lower() if kind == "users" else value.strip()
        items = set(known.get(kind, []) or [])
        items.add(value)
        known[kind] = sorted(items)
        _save_known(conn, tenant, known)
        _reapply_suppression(conn, tenant_id, cfg.get_tenant(conn, tenant_id))
        return RedirectResponse(url=f"/t/{tenant_id}/known", status_code=303)

    @app.post("/t/{tenant_id}/known/remove")
    def known_remove(request: Request, tenant_id: str, conn=Depends(db_conn),
                      kind: str = Form(...), value: str = Form(...)):
        tenant = cfg.get_tenant(conn, tenant_id)
        if not tenant or kind not in ("users", "ips"):
            return RedirectResponse(url=f"/t/{tenant_id}/known", status_code=303)
        known = dict(tenant.known or {})
        known[kind] = [v for v in (known.get(kind, []) or []) if v != value]
        _save_known(conn, tenant, known)
        return RedirectResponse(url=f"/t/{tenant_id}/known", status_code=303)

    # --- Admin: tenants/servers ------------------------------------------------------------

    @app.get("/admin/tenants")
    def admin_tenants(request: Request, conn=Depends(db_conn)):
        tenants = cfg.load_tenants(conn, include_disabled=True)
        health = {}
        with conn.cursor() as cur:
            for t in tenants:
                cur.execute("""SELECT started_at, finished_at, error FROM runs
                               WHERE tenant_id=%s AND kind <> 'backfill'
                               ORDER BY started_at DESC LIMIT 1""", (t.id,))
                health[t.id] = cur.fetchone()
        return render(request, "admin_tenants.html", {"tenants": tenants, "health": health})

    @app.get("/admin/tenants/new")
    def admin_tenant_new_form(request: Request):
        return render(request, "admin_tenant_form.html", {"t": None, "row": None, "error": None})

    @app.get("/admin/tenants/{tenant_id}/edit")
    def admin_tenant_edit_form(request: Request, tenant_id: str, conn=Depends(db_conn)):
        row = cfg.get_tenant_row(conn, tenant_id)
        if not row:
            return render(request, "not_found.html", {"tenant": None}, status_code=404)
        with conn.cursor() as cur:
            cur.execute("""SELECT settings, taken_at FROM settings_snapshots
                           WHERE tenant_id=%s ORDER BY taken_at DESC LIMIT 1""", (tenant_id,))
            snap = cur.fetchone()
        log_settings = _decode_log_settings(snap["settings"], snap["taken_at"], row["display_tz"]) if snap else None
        return render(request, "admin_tenant_form.html", {
            "t": tenant_id, "row": _augment_schedule(row), "error": None, "log_settings": log_settings})

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
                             schedule_hour: int = Form(3), schedule_minute: int = Form(30),
                             use_advanced_schedule: bool = Form(False), schedule_cron_advanced: str = Form(""),
                             llm_enabled: bool = Form(False), llm_redact: bool = Form(False),
                             digest_email_to: str = Form(""), digest_only_on_new: bool = Form(False),
                             enabled: bool = Form(False)):
        if cfg.get_tenant_row(conn, id):
            return render(request, "admin_tenant_form.html",
                          {"t": None, "row": None, "error": f"Tenant '{id}' already exists"}, status_code=400)
        schedule_cron = _compute_schedule_cron(schedule_hour, schedule_minute, use_advanced_schedule, schedule_cron_advanced)
        cfg.save_tenant(conn, id=id, base_url=base_url, username=username, password=password,
                        tenant_name_override=tenant_name_override or None,
                        log_category_no=log_category_no, log_tz=log_tz, display_tz=display_tz,
                        schedule_cron=schedule_cron, llm_enabled=llm_enabled, llm_redact=llm_redact,
                        digest_email_to=_split_emails(digest_email_to),
                        digest_only_on_new=digest_only_on_new, known={}, enabled=enabled)
        return RedirectResponse(url="/admin/tenants", status_code=303)

    @app.post("/admin/tenants/{tenant_id}/edit")
    def admin_tenant_update(request: Request, tenant_id: str, conn=Depends(db_conn),
                             base_url: str = Form(...), username: str = Form(""),
                             password: str = Form(""), tenant_name_override: str = Form(""),
                             log_category_no: int = Form(1), log_tz: str = Form("UTC"),
                             display_tz: str = Form("UTC"),
                             schedule_hour: int = Form(3), schedule_minute: int = Form(30),
                             use_advanced_schedule: bool = Form(False), schedule_cron_advanced: str = Form(""),
                             llm_enabled: bool = Form(False), llm_redact: bool = Form(False),
                             digest_email_to: str = Form(""), digest_only_on_new: bool = Form(False),
                             enabled: bool = Form(False)):
        existing = cfg.get_tenant(conn, tenant_id)
        schedule_cron = _compute_schedule_cron(schedule_hour, schedule_minute, use_advanced_schedule, schedule_cron_advanced)
        cfg.save_tenant(conn, id=tenant_id, base_url=base_url, username=username,
                        password=(password or None), tenant_name_override=tenant_name_override or None,
                        log_category_no=log_category_no, log_tz=log_tz, display_tz=display_tz,
                        schedule_cron=schedule_cron, llm_enabled=llm_enabled, llm_redact=llm_redact,
                        digest_email_to=_split_emails(digest_email_to),
                        digest_only_on_new=digest_only_on_new,
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
        # app.state.settings.smtp is whatever load_settings() set at process startup (empty
        # defaults - SMTP is DB-config, not env) and nothing else in the web app ever refreshes
        # it, unlike the CLI and scheduler which both do this on every invocation. Without this,
        # write_and_send()'s `if smtp.get("host")` check silently (no error, no log line) skips
        # sending - "Run now" would produce a report but never email it, however SMTP is
        # configured or how recently.
        cfg.refresh_from_db(request.app.state.settings, conn)
        stats = run_tenant(request.app.state.settings, tenant)
        return render(request, "admin_tenant_run_result.html", {"tenant_id": tenant_id, "stats": stats})

    @app.get("/admin/tenants/{tenant_id}/rules")
    def admin_tenant_rules(request: Request, tenant_id: str, conn=Depends(db_conn)):
        from ..rules import builtin  # noqa: F401  (registers rules)
        from ..rules.engine import RULES
        from ..rules.settings_schema import RULE_FIELDS
        settings: Settings = request.app.state.settings
        overrides = cfg.rule_settings_for(conn, tenant_id)
        rows = []
        for rule_id in sorted(RULES):
            global_default = bool(settings.rules.get(rule_id, {}).get("enabled", True))
            ov = overrides.get(rule_id, {})
            override_config = ov.get("config") or {}
            fields = []
            for key, ftype, label, help_text in RULE_FIELDS.get(rule_id, []):
                default_val = settings.rules.get(rule_id, {}).get(key)
                value = override_config[key] if key in override_config else default_val
                if ftype == "userlist":
                    value = "\n".join(value or [])
                fields.append({"key": key, "type": ftype, "label": label, "help": help_text, "value": value})
            rows.append({"rule_id": rule_id, "global_default": global_default,
                        "enabled": ov.get("enabled"), "fields": fields})
        return render(request, "admin_tenant_rules.html", {"tenant_id": tenant_id, "rows": rows})

    @app.post("/admin/tenants/{tenant_id}/rules")
    async def admin_tenant_rules_save(request: Request, tenant_id: str, conn=Depends(db_conn)):
        from ..rules import builtin  # noqa: F401
        from ..rules.engine import RULES
        from ..rules.settings_schema import RULE_FIELDS
        settings: Settings = request.app.state.settings
        form = await request.form()
        for rule_id in RULES:
            choice = form.get(f"enabled__{rule_id}", "inherit")
            enabled = {"inherit": None, "on": True, "off": False}.get(choice)
            defaults = settings.rules.get(rule_id, {})
            config_obj: dict = {}
            for key, ftype, _, _ in RULE_FIELDS.get(rule_id, []):
                raw = form.get(f"{rule_id}__{key}", "")
                try:
                    if ftype == "int":
                        value = int(raw)
                    elif ftype == "float":
                        value = float(raw)
                    else:   # userlist
                        value = _split_lines(raw)
                except ValueError:
                    continue   # leave that one field at its current value rather than 500
                if value != defaults.get(key):   # only store what actually differs from the default
                    config_obj[key] = value
            cfg.set_rule_setting(conn, tenant_id, rule_id, enabled, config_obj)
        return RedirectResponse(url=f"/admin/tenants/{tenant_id}/rules", status_code=303)

    # --- Admin: SMTP -------------------------------------------------------------------

    @app.get("/admin/smtp")
    def admin_smtp_form(request: Request, conn=Depends(db_conn)):
        smtp = cfg.load_smtp(conn) or {"host": "", "port": 587, "user": "", "from": "", "starttls": True}
        return render(request, "admin_smtp.html", {"smtp": smtp, "saved": False, "general": cfg.load_general(conn)})

    @app.post("/admin/smtp")
    def admin_smtp_save(request: Request, conn=Depends(db_conn), host: str = Form(""),
                         port: int = Form(587), user: str = Form(""), password: str = Form(""),
                         from_addr: str = Form(""), starttls: bool = Form(False)):
        cfg.save_smtp(conn, host=host, port=port, user=user, password=(password or None),
                      from_addr=from_addr, starttls=starttls)
        smtp = cfg.load_smtp(conn)
        return render(request, "admin_smtp.html", {"smtp": smtp, "saved": True, "general": cfg.load_general(conn)})

    @app.post("/admin/general")
    def admin_general_save(request: Request, conn=Depends(db_conn), dashboard_url: str = Form(""),
                            alert_email_to: str = Form("")):
        cfg.save_general(conn, dashboard_url=dashboard_url, alert_email_to=_split_emails(alert_email_to))
        smtp = cfg.load_smtp(conn) or {"host": "", "port": 587, "user": "", "from": "", "starttls": True}
        return render(request, "admin_smtp.html", {"smtp": smtp, "saved": True, "general": cfg.load_general(conn)})

    @app.post("/admin/smtp/test")
    def admin_smtp_test(request: Request, conn=Depends(db_conn), host: str = Form(""),
                         port: int = Form(587), user: str = Form(""), password: str = Form(""),
                         from_addr: str = Form(""), starttls: bool = Form(False), test_to: str = Form("")):
        from .. import digest
        user_obj = auth.current_user(request)
        test_to = test_to.strip()
        if not test_to:
            test_result = {"ok": False, "message": "Enter an address to send the test email to."}
        elif not host:
            test_result = {"ok": False, "message": "Enter an SMTP host first."}
        else:
            # A blank password means "keep the saved one" everywhere else in this app, so a
            # test without retyping it should behave the same way rather than trying anonymous auth.
            pw = password or (cfg.load_smtp(conn) or {}).get("password", "")
            smtp = {"host": host, "port": port, "user": user, "password": pw,
                    "from": from_addr, "starttls": starttls}
            try:
                digest.send_email(smtp, [test_to], "Therefore Log Auditor - test email",
                                  f"This is a test email from the Therefore Log Auditor dashboard's "
                                  f"SMTP settings, sent by {user_obj.username if user_obj else 'a dashboard user'}.")
                test_result = {"ok": True, "message": f"Test email sent to {test_to}."}
            except Exception as exc:
                test_result = {"ok": False, "message": f"Could not send: {exc}"}
        # Echo back whatever password was typed for this test (only here, only right after a
        # test) - otherwise a password typed just to try it out vanishes from the form, and a
        # Save right after the test silently keeps the OLD saved password instead of the one
        # that was just confirmed to work.
        smtp_display = {"host": host, "port": port, "user": user, "from": from_addr,
                        "starttls": starttls, "password": password}
        return render(request, "admin_smtp.html", {
            "smtp": smtp_display, "saved": False, "test_result": test_result, "test_to": test_to,
            "general": cfg.load_general(conn)})

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
    advanced = bool(get("use_advanced_schedule"))
    try:
        hour, minute = int(get("schedule_hour") or 3), int(get("schedule_minute") or 30)
    except ValueError:
        hour, minute = 3, 30
    cron_advanced = get("schedule_cron_advanced", "")
    return {
        "base_url": get("base_url"), "therefore_username": get("username"),
        "password": get("password"),   # echoed back so a successful test doesn't need retyping
        "tenant_name_override": get("tenant_name_override"),
        "log_category_no": int(get("log_category_no") or 1), "log_tz": get("log_tz", "UTC"),
        "display_tz": get("display_tz", "UTC"),
        "schedule_cron": _compute_schedule_cron(hour, minute, advanced, cron_advanced),
        "schedule_hour": hour, "schedule_minute": minute, "schedule_advanced": advanced,
        "schedule_cron_advanced": cron_advanced,
        "llm_enabled": bool(get("llm_enabled")), "llm_redact": bool(get("llm_redact")),
        "digest_email_to": _split_emails(get("digest_email_to")),
        "digest_only_on_new": bool(get("digest_only_on_new")), "enabled": bool(get("enabled")),
    }


def _group_for_display(findings: list[dict], display_tz: str) -> list[dict]:
    """Collapse findings that share a rule and calendar day into one expandable row when
    there are 3 or more - e.g. 130 separate "New user: X" rows become one "130 new_entity
    findings on 28 Sep" row you can open, instead of 130 lines of near-identical noise.
    Order-preserving: a group appears where its first (most recent) member would have."""
    tz = ZoneInfo(display_tz)
    buckets: dict[tuple, list[dict]] = {}
    for f in findings:
        key = (f["rule_id"], f["last_ts"].astimezone(tz).date())
        buckets.setdefault(key, []).append(f)

    items: list[dict] = []
    seen: set[tuple] = set()
    for f in findings:
        key = (f["rule_id"], f["last_ts"].astimezone(tz).date())
        if key in seen:
            continue
        seen.add(key)
        bucket = buckets[key]
        if len(bucket) >= 3:
            worst = min(bucket, key=lambda x: SEV_ORDER[x["severity"]])
            items.append({"kind": "group", "rule_id": key[0], "day": key[1], "members": bucket,
                          "severity": worst["severity"]})
        else:
            items.extend({"kind": "row", "f": b} for b in bucket)
    return items


def _split_emails(raw: str) -> list[str]:
    return [e.strip() for e in raw.replace(",", "\n").splitlines() if e.strip()]


def _split_lines(raw: str) -> list[str]:
    return [line.strip() for line in raw.splitlines() if line.strip()]


_DAILY_CRON_RE = re.compile(r"^\s*(\d{1,2})\s+(\d{1,2})\s+\*\s+\*\s+\*\s*$")


def _compute_schedule_cron(hour: int, minute: int, advanced: bool, raw_cron: str) -> str:
    """The stored schedule is always a plain cron string (scheduler.py just hands it to
    CronTrigger.from_crontab), but almost everyone only wants "run once a day at HH:MM" - so
    the form offers a time picker by default and only asks for real cron syntax if you opt in."""
    if advanced:
        return (raw_cron or "").strip() or "30 3 * * *"
    hour = max(0, min(23, hour))
    minute = max(0, min(59, minute))
    return f"{minute} {hour} * * *"


def _augment_schedule(row: dict) -> dict:
    """Adds schedule_hour/schedule_minute/schedule_advanced/schedule_cron_advanced to a tenant
    row (from the database) so the form can default to the simple time picker, only falling
    back to showing raw cron when the stored schedule isn't a plain daily "M H * * *" pattern."""
    cron = row.get("schedule_cron") or "30 3 * * *"
    m = _DAILY_CRON_RE.match(cron)
    if m and int(m.group(1)) < 60 and int(m.group(2)) < 24:
        row["schedule_minute"], row["schedule_hour"], row["schedule_advanced"] = int(m.group(1)), int(m.group(2)), False
    else:
        row["schedule_hour"], row["schedule_minute"], row["schedule_advanced"] = 3, 30, True
    row["schedule_cron_advanced"] = cron
    return row


_WINDOW_RE = re.compile(r"^(?P<start>.+?)\s+to\s+(?P<end>.+):\s*(?P<note>.*)$")


ARCHIVE_MODES = {1: "Every day"}   # other values are weekly/monthly/by-size, not yet mapped
LOGMASK_LABELS = {0: "Do not log", 1: "Log failure", 2: "Log success", 3: "Log always"}


def _decode_log_settings(settings: dict, taken_at, display_tz: str) -> dict:
    """Turns the raw GetSettings snapshot (keys 700-704, see the Server Settings section of
    the therefore-api skill) into something readable on the tenant page. The LogMask (700) is
    52 positional values whose position->event mapping isn't established yet (needs toggling
    one event at a time in Solution Designer and diffing) - so it's shown as counts + a raw
    per-position grid rather than named events."""
    positions = [int(v) for v in re.findall(r"<V>(\d+)</V>", str(settings.get("700") or ""))]
    counts: dict[int, int] = {}
    for v in positions:
        counts[v] = counts.get(v, 0) + 1
    archive_mode = settings.get("701")
    archive_time_min = settings.get("703")
    archive_time_utc = archive_time_local = None
    if isinstance(archive_time_min, int):
        h, m = divmod(archive_time_min, 60)
        archive_time_utc = f"{h:02d}:{m:02d} UTC"
        local_dt = dt.datetime.now(dt.timezone.utc).replace(hour=h % 24, minute=m, second=0, microsecond=0)
        archive_time_local = local_dt.astimezone(ZoneInfo(display_tz)).strftime("%H:%M %Z")
    return {
        "taken_at": taken_at,
        "archive_mode": ARCHIVE_MODES.get(archive_mode, f"Mode {archive_mode} (unmapped)") if archive_mode is not None else None,
        "archive_weekday": settings.get("702"),
        "archive_time_utc": archive_time_utc,
        "archive_time_local": archive_time_local,
        "split_size_mb": settings.get("704"),
        "logmask_positions": positions,
        "logmask_counts": [{"value": v, "label": LOGMASK_LABELS.get(v, f"Value {v}"), "count": c}
                          for v, c in sorted(counts.items())],
    }


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
