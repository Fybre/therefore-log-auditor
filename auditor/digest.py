"""Daily digest: an HTML/Markdown report written to reports/ and optionally emailed."""
from __future__ import annotations

import datetime as dt
import html
import logging
import smtplib
from email.message import EmailMessage
from pathlib import Path
from zoneinfo import ZoneInfo

import psycopg

from .config import Settings, Tenant

log = logging.getLogger(__name__)

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
SEV_COLOUR = {"high": "#b42318", "medium": "#b54708", "low": "#475467", "info": "#98a2b3"}


def gather(conn: psycopg.Connection, tenant: Tenant, since: dt.datetime) -> dict:
    with conn.cursor() as cur:
        cur.execute("""SELECT * FROM findings WHERE tenant_id=%s AND updated_at >= %s
                       ORDER BY array_position(ARRAY['high','medium','low','info'], severity), last_ts DESC""",
                    (tenant.id, since))
        findings = cur.fetchall()
        cur.execute("""SELECT application, max(generated) AS generated, max(last_ts) AS last_event,
                              max(fetched_at) AS fetched
                       FROM log_files WHERE tenant_id=%s AND status='parsed' GROUP BY 1 ORDER BY 1""", (tenant.id,))
        freshness = cur.fetchall()
        cur.execute("""SELECT action, success, count(*) AS n FROM events
                       WHERE tenant_id=%s AND source='server' AND ts >= %s GROUP BY 1, 2 ORDER BY 3 DESC""",
                    (tenant.id, since - dt.timedelta(days=1)))
        activity = cur.fetchall()
        cur.execute("""SELECT count(*) AS n FROM log_files WHERE tenant_id=%s AND status='error'""", (tenant.id,))
        errors = cur.fetchone()["n"]
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    return {"findings": findings, "freshness": freshness, "activity": activity, "counts": counts,
            "file_errors": errors}


def render(tenant: Tenant, data: dict, summary: dict | None, run_stats: dict) -> tuple[str, str, str]:
    tz = ZoneInfo(tenant.display_tz)
    today = dt.datetime.now(tz).strftime("%a %d %b %Y")
    c = data["counts"]
    subject = f"[Therefore audit] {tenant.id} {today}: {c['high']} high, {c['medium']} medium"
    if summary:
        subject += f" - {summary['headline'][:80]}"

    def local(ts):
        return ts.astimezone(tz).strftime("%d %b %H:%M") if ts else "-"

    # Markdown
    md = [f"# Therefore audit - {tenant.id} - {today}", ""]
    if summary:
        md += [f"**{summary['headline']}**", "", summary["summary"], ""]
    md += [f"Findings updated this run: {c['high']} high, {c['medium']} medium, {c['low']} low, {c['info']} info.", ""]
    for f in data["findings"]:
        if f["severity"] == "info":
            continue
        md.append(f"## [{f['severity'].upper()}] {f['title']}")
        md.append(f"{local(f['first_ts'])} to {local(f['last_ts'])} ({tenant.display_tz}) - rule `{f['rule_id']}`"
                  + (f", LLM verdict: {f['llm_verdict']}" if f["llm_verdict"] else ""))
        if f["llm_explanation"]:
            md += ["", f["llm_explanation"]]
        for a in f["llm_actions"] or []:
            md.append(f"- {a}")
        md.append("")
    info = [f for f in data["findings"] if f["severity"] == "info"]
    if info:
        md += ["## Expected / suppressed", ""] + [f"- {f['title']} ({f['suppressed_by'] or f['llm_verdict']})" for f in info] + [""]
    md += ["## Log freshness", ""] + [
        f"- {r['application']}: last file {r['generated']}, last event {local(r['last_event'])}" for r in data["freshness"]]
    md += ["", f"Run: {run_stats}"]

    # HTML
    rows = []
    for f in data["findings"]:
        if f["severity"] == "info":
            continue
        actions = "".join(f"<li>{html.escape(a)}</li>" for a in (f["llm_actions"] or []))
        rows.append(f"""
<tr><td style="padding:12px 0;border-top:1px solid #eaecf0">
  <span style="color:#fff;background:{SEV_COLOUR[f['severity']]};border-radius:4px;padding:2px 6px;font-size:11px;font-weight:600">{f['severity'].upper()}</span>
  <strong style="margin-left:6px">{html.escape(f['title'])}</strong>
  <div style="color:#667085;font-size:12px;margin-top:4px">{local(f['first_ts'])} to {local(f['last_ts'])} &middot; {html.escape(f['rule_id'])}
  {('&middot; verdict: ' + html.escape(f['llm_verdict'])) if f['llm_verdict'] else ''}</div>
  {('<p style="margin:6px 0">' + html.escape(f['llm_explanation']) + '</p>') if f['llm_explanation'] else ''}
  {('<ul style="margin:4px 0 0 18px;padding:0">' + actions + '</ul>') if actions else ''}
</td></tr>""")
    fresh = "".join(f"<li>{html.escape(r['application'])}: last file {r['generated']}, last event {local(r['last_event'])}</li>"
                    for r in data["freshness"])
    info_html = "".join(f"<li>{html.escape(f['title'])} <span style='color:#98a2b3'>({html.escape(f['suppressed_by'] or f['llm_verdict'] or '')})</span></li>" for f in info)
    body = f"""<!doctype html><html><body style="font-family:-apple-system,Segoe UI,Arial,sans-serif;color:#101828;max-width:720px;margin:0 auto;padding:16px">
<h2 style="margin:0 0 4px">Therefore audit &middot; {html.escape(tenant.id)}</h2>
<div style="color:#667085">{today}</div>
{('<p style="font-size:16px;margin:16px 0 4px"><strong>' + html.escape(summary['headline']) + '</strong></p><p style="margin:0 0 12px">' + html.escape(summary['summary']) + '</p>') if summary else ''}
<p>{c['high']} high &middot; {c['medium']} medium &middot; {c['low']} low &middot; {c['info']} info</p>
<table style="width:100%;border-collapse:collapse">{''.join(rows) or '<tr><td>No findings need attention.</td></tr>'}</table>
{('<h3>Expected / suppressed</h3><ul>' + info_html + '</ul>') if info_html else ''}
<h3>Log freshness</h3><ul>{fresh}</ul>
<p style="color:#98a2b3;font-size:12px">Run: {html.escape(str(run_stats))}</p>
</body></html>"""
    return subject, "\n".join(md), body


def write_and_send(settings: Settings, tenant: Tenant, subject: str, md: str, body_html: str) -> Path:
    out_dir = settings.reports_dir / tenant.id
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(ZoneInfo(tenant.display_tz)).strftime("%Y-%m-%d_%H%M")
    (out_dir / f"{stamp}.md").write_text(md)
    path = out_dir / f"{stamp}.html"
    path.write_text(body_html)
    to = (tenant.digest or {}).get("email_to") or []
    smtp = settings.smtp
    if to and smtp.get("host"):
        msg = EmailMessage()
        msg["Subject"], msg["From"], msg["To"] = subject, smtp.get("from") or smtp.get("user"), ", ".join(to)
        msg.set_content(md)
        msg.add_alternative(body_html, subtype="html")
        try:
            with smtplib.SMTP(smtp["host"], smtp["port"], timeout=30) as s:
                if smtp.get("starttls"):
                    s.starttls()
                if smtp.get("user"):
                    s.login(smtp["user"], smtp["password"])
                s.send_message(msg)
            log.info("Digest emailed to %s", to)
        except Exception:
            log.exception("Sending digest email failed (report still written to %s)", path)
    return path
