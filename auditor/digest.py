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

from . import link_tokens
from .config import Settings, Tenant

log = logging.getLogger(__name__)

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
SEV_COLOUR = {"high": "#b42318", "medium": "#b54708", "low": "#475467", "info": "#98a2b3"}


def _incident_groups(findings: list[dict]) -> list[list[dict]]:
    """Findings sharing an incident_key (same triage call, see llm.triage) render as one entry."""
    groups: dict[str, list[dict]] = {}
    for f in findings:
        groups.setdefault(f["incident_key"] or f"solo:{f['id']}", []).append(f)
    return list(groups.values())


def gather(conn: psycopg.Connection, tenant: Tenant, since: dt.datetime) -> dict:
    with conn.cursor() as cur:
        cur.execute("""SELECT * FROM findings WHERE tenant_id=%s AND updated_at >= %s
                       ORDER BY array_position(ARRAY['high','medium','low','info'], severity), last_ts DESC""",
                    (tenant.id, since))
        findings = cur.fetchall()
        # Everything still open, regardless of whether it changed in this run - `counts` below
        # only covers what's in `findings` (today's new/changed), so without this the digest
        # can only ever say what happened today, never what's still outstanding overall.
        cur.execute("""SELECT severity, count(*) AS n FROM findings
                       WHERE tenant_id=%s AND status='open' GROUP BY 1""", (tenant.id,))
        open_counts = {s: 0 for s in SEV_ORDER}
        open_counts.update({r["severity"]: r["n"] for r in cur.fetchall()})
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
            "open_counts": open_counts, "file_errors": errors}


def render(tenant: Tenant, data: dict, summary: dict | None,
          dashboard_url: str = "", review_secret: str = "") -> tuple[str, str, str]:
    dashboard_url = (dashboard_url or "").rstrip("/")
    tz = ZoneInfo(tenant.display_tz)
    today = dt.datetime.now(tz).strftime("%a %d %b %Y")
    c = data["counts"]
    oc = data.get("open_counts") or {s: 0 for s in SEV_ORDER}
    subject = f"[Therefore audit] {tenant.id} {today}: {c['high']} high, {c['medium']} medium"
    if summary:
        subject += f" - {summary['headline'][:80]}"

    findings_url = f"{dashboard_url}/t/{tenant.id}/findings" if dashboard_url else None

    def local(ts):
        return ts.astimezone(tz).strftime("%d %b %H:%M") if ts else "-"

    def finding_url(f):
        return f"{dashboard_url}/t/{tenant.id}/findings/{f['id']}" if dashboard_url else None

    def review_url(f, action):
        if not dashboard_url:
            return None
        token = link_tokens.make_token(review_secret, tenant.id, f["id"], action)
        return f"{dashboard_url}/review/{token}" if token else None

    # Markdown
    md = [f"# Therefore audit - {tenant.id} - {today}", ""]
    if summary:
        md += [f"**{summary['headline']}**", "", summary["summary"], ""]
    md += [f"**Currently open: {oc['high']} high, {oc['medium']} medium, {oc['low']} low** "
           f"(all-time backlog, not just today) - updated this run: {c['high']} high, "
           f"{c['medium']} medium, {c['low']} low, {c['info']} info.", ""]
    if findings_url:
        md += [f"[Open the dashboard]({findings_url}) - filter, review, and manage known activity there.", ""]
    visible = [f for f in data["findings"] if f["severity"] != "info"]
    for group in _incident_groups(visible):
        head = min(group, key=lambda f: SEV_ORDER[f["severity"]])
        titles = list(dict.fromkeys(f["title"] for f in group))
        rules = ", ".join(sorted({f["rule_id"] for f in group}))
        span_start = min(f["first_ts"] for f in group)
        span_end = max(f["last_ts"] for f in group)
        url = finding_url(head)
        heading = f"[{titles[0]}]({url})" if url else titles[0]
        md.append(f"## [{head['severity'].upper()}] {heading}")
        md.append(f"{local(span_start)} to {local(span_end)} ({tenant.display_tz}) - rule(s) `{rules}`"
                  + (f", LLM verdict: {head['llm_verdict']}" if head["llm_verdict"] else ""))
        if len(group) > 1:
            md += [""] + [f"- {t}" for t in titles]
        if head["llm_explanation"]:
            md += ["", head["llm_explanation"]]
        for a in head["llm_actions"] or []:
            md.append(f"- {a}")
        ack_url, fp_url = review_url(head, "acknowledged"), review_url(head, "false_positive")
        if ack_url and fp_url:
            md += ["", f"[Mark reviewed]({ack_url}) | [False positive]({fp_url})"]
        md.append("")
    info = [f for f in data["findings"] if f["severity"] == "info"]
    if info:
        md += ["## Expected / suppressed", ""] + [f"- {f['title']} ({f['suppressed_by'] or f['llm_verdict']})" for f in info] + [""]
    md += ["## Log freshness", ""] + [
        f"- {r['application']}: last file {r['generated']}, last event {local(r['last_event'])}" for r in data["freshness"]]

    # HTML
    rows = []
    for group in _incident_groups(visible):
        head = min(group, key=lambda f: SEV_ORDER[f["severity"]])
        titles = list(dict.fromkeys(f["title"] for f in group))
        rules = ", ".join(sorted({f["rule_id"] for f in group}))
        span_start = min(f["first_ts"] for f in group)
        span_end = max(f["last_ts"] for f in group)
        actions = "".join(f"<li>{html.escape(a)}</li>" for a in (head["llm_actions"] or []))
        members_html = ("<ul style='margin:4px 0 0 18px;padding:0'>"
                         + "".join(f"<li>{html.escape(t)}</li>" for t in titles) + "</ul>") if len(group) > 1 else ""
        url = finding_url(head)
        title_html = (f'<a href="{html.escape(url)}" style="color:#101828;text-decoration:underline">'
                      f'{html.escape(titles[0])}</a>') if url else html.escape(titles[0])
        ack_url, fp_url = review_url(head, "acknowledged"), review_url(head, "false_positive")
        review_links_html = (
            f'<div style="margin-top:6px;font-size:12px">'
            f'<a href="{html.escape(ack_url)}" style="color:#0369a1">Mark reviewed</a>'
            f' &middot; <a href="{html.escape(fp_url)}" style="color:#0369a1">False positive</a></div>'
        ) if ack_url and fp_url else ""
        rows.append(f"""
<tr><td style="padding:12px 0;border-top:1px solid #eaecf0">
  <span style="color:#fff;background:{SEV_COLOUR[head['severity']]};border-radius:4px;padding:2px 6px;font-size:11px;font-weight:600">{head['severity'].upper()}</span>
  <strong style="margin-left:6px">{title_html}</strong>
  <div style="color:#667085;font-size:12px;margin-top:4px">{local(span_start)} to {local(span_end)} &middot; {html.escape(rules)}
  {('&middot; verdict: ' + html.escape(head['llm_verdict'])) if head['llm_verdict'] else ''}</div>
  {members_html}
  {('<p style="margin:6px 0">' + html.escape(head['llm_explanation']) + '</p>') if head['llm_explanation'] else ''}
  {('<ul style="margin:4px 0 0 18px;padding:0">' + actions + '</ul>') if actions else ''}
  {review_links_html}
</td></tr>""")
    fresh = "".join(f"<li>{html.escape(r['application'])}: last file {r['generated']}, last event {local(r['last_event'])}</li>"
                    for r in data["freshness"])
    info_html = "".join(f"<li>{html.escape(f['title'])} <span style='color:#98a2b3'>({html.escape(f['suppressed_by'] or f['llm_verdict'] or '')})</span></li>" for f in info)
    dashboard_link_html = (f'<p style="margin:8px 0 16px"><a href="{html.escape(findings_url)}" '
                           f'style="color:#101828;font-weight:600">Open the dashboard &rarr;</a></p>') if findings_url else ""
    body = f"""<!doctype html><html><body style="font-family:-apple-system,Segoe UI,Arial,sans-serif;color:#101828;max-width:720px;margin:0 auto;padding:16px">
<h2 style="margin:0 0 4px">Therefore audit &middot; {html.escape(tenant.id)}</h2>
<div style="color:#667085">{today}</div>
{('<p style="font-size:16px;margin:16px 0 4px"><strong>' + html.escape(summary['headline']) + '</strong></p><p style="margin:0 0 12px">' + html.escape(summary['summary']) + '</p>') if summary else ''}
<p><strong>Currently open: {oc['high']} high, {oc['medium']} medium, {oc['low']} low</strong>
<span style="color:#667085">(all-time backlog, not just today)</span></p>
<p style="color:#667085;margin:0 0 8px">Updated this run: {c['high']} high &middot; {c['medium']} medium &middot; {c['low']} low &middot; {c['info']} info</p>
{dashboard_link_html}
<table style="width:100%;border-collapse:collapse">{''.join(rows) or '<tr><td>No findings need attention.</td></tr>'}</table>
{('<h3>Expected / suppressed</h3><ul>' + info_html + '</ul>') if info_html else ''}
<h3>Log freshness</h3><ul>{fresh}</ul>
</body></html>"""
    return subject, "\n".join(md), body


def send_email(smtp: dict, to: list[str], subject: str, text: str, html: str | None = None) -> None:
    """Raises on failure - callers decide whether to swallow it (write_and_send logs and
    moves on so a broken SMTP config never blocks the report being written) or surface it
    (the SMTP settings page's "Send test email")."""
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, smtp.get("from") or smtp.get("user"), ", ".join(to)
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    with smtplib.SMTP(smtp["host"], smtp["port"], timeout=30) as s:
        if smtp.get("starttls"):
            s.starttls()
        if smtp.get("user"):
            s.login(smtp["user"], smtp["password"])
        s.send_message(msg)


def write_and_send(settings: Settings, tenant: Tenant, subject: str, md: str, body_html: str,
                    has_new_findings: bool = True) -> Path:
    out_dir = settings.reports_dir / tenant.id
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(ZoneInfo(tenant.display_tz)).strftime("%Y-%m-%d_%H%M")
    (out_dir / f"{stamp}.md").write_text(md)
    path = out_dir / f"{stamp}.html"
    path.write_text(body_html)
    to = (tenant.digest or {}).get("email_to") or []
    smtp = settings.smtp
    if (tenant.digest or {}).get("only_on_new") and not has_new_findings:
        log.info("Digest not emailed for %s: no new findings this run and only_on_new is set "
                 "(report still written to %s)", tenant.id, path)
    elif to and smtp.get("host"):
        try:
            send_email(smtp, to, subject, md, body_html)
            log.info("Digest emailed to %s", to)
        except Exception:
            log.exception("Sending digest email failed (report still written to %s)", path)
    return path
