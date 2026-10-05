"""Security notification outbox: episode deduplication, escalation, and resilient SMTP delivery."""
from __future__ import annotations

import datetime as dt
import html
import logging
import re
from typing import Any

from .. import config, digest

log = logging.getLogger(__name__)

UTC = dt.timezone.utc

RULE_TITLES = {
    'login_failures': 'Repeated credential failures',
    'password_spray': 'Possible password spray',
    'success_after_failures': 'Successful login after failures',
    'retrieval_burst': 'Document retrieval burst',
    'api_activity_burst': 'Observed API activity burst',
}


def rule_title(rule_id: str) -> str:
    return RULE_TITLES.get(rule_id, rule_id.replace('_', ' ').title())


def severity_for(rule_id: str, details: dict[str, Any]) -> str:
    if rule_id in ('login_failures', 'password_spray', 'success_after_failures'):
        return 'high'
    count = int(details.get('count', 0))
    limit = int(details.get('limit', 100))
    if limit > 0 and count >= 5 * limit:
        return 'high'
    return 'medium'


def rule_summary(rule_id: str, details: dict[str, Any], subject: str) -> str:
    count = details.get('count', 0)
    limit = details.get('limit')
    if rule_id == 'login_failures':
        return f"Account '{subject}' had {count} credential failures within 15 minutes."
    if rule_id == 'password_spray':
        return f"IP address {subject} attempted logins across {count} distinct accounts within 60 minutes."
    if rule_id == 'success_after_failures':
        return f"Account '{subject}' connected successfully after {count} credential failures within 2 hours."
    if rule_id == 'retrieval_burst':
        return f"Account '{subject}' retrieved {count} distinct documents within 5 minutes (threshold: {limit})."
    if rule_id == 'api_activity_burst':
        return f"Account '{subject}' performed {count} observed API operations within 5 minutes (threshold: {limit})."
    return f"Rule {rule_id} triggered for {subject} (count: {count})."


def parse_recipients(alert_recipients: str, fallback_recipients: list[str]) -> list[str]:
    values = alert_recipients.replace(',', '\n').splitlines() if alert_recipients.strip() else fallback_recipients
    cleaned = []
    for value in values:
        addr = value.strip()
        if not addr:
            continue
        if len(addr) > 254 or not re.fullmatch(r'[^\s@<>,;]+@[^\s@<>,;]+\.[^\s@<>,;]+', addr):
            raise ValueError('Enter valid email addresses separated by commas or new lines.')
        if addr not in cleaned:
            cleaned.append(addr)
    if len(cleaned) > 50:
        raise ValueError('Use no more than 50 alert recipients.')
    return cleaned


def determine_alert(old_row: dict[str, Any] | None, new_finding: dict[str, Any],
                    now: dt.datetime) -> tuple[str, str] | None:
    """Check if a finding should generate an outbox alert.

    Returns (alert_type, severity) or None.
    - alert_type is 'initial' or 'escalation'.
    - Routine activity within an ongoing episode does not alert.
    - Escalation requires >= 15m since last alert AND (count doubled OR severity increased).
    - Expected/approved activity never alerts.
    """
    if new_finding.get('expected'):
        return None

    details = new_finding.get('details', {})
    sev = severity_for(new_finding['rule_id'], details)
    count = int(details.get('count', 0))

    if not old_row or not old_row.get('alert_count'):
        return 'initial', sev

    last_alert_ts = old_row.get('last_alert_ts')
    if not last_alert_ts:
        return 'initial', sev

    # Rate-limit escalations to at most once per 15 minutes
    if (now - last_alert_ts) < dt.timedelta(minutes=15):
        return None

    old_count = int(old_row.get('last_alert_count') or 0)
    old_sev = str(old_row.get('last_alert_severity') or 'medium')

    count_doubled = old_count > 0 and count >= 2 * old_count
    sev_escalated = (old_sev == 'medium' and sev == 'high')

    if count_doubled or sev_escalated:
        return 'escalation', sev

    return None


def format_alert_email(tenant_id: str, finding_id: int | None, rule_id: str,
                       subject_str: str, details: dict[str, Any], first_ts: dt.datetime,
                       last_ts: dt.datetime, alert_type: str, severity: str,
                       base_url: str = "") -> tuple[str, str, str]:
    details = dict(details)
    if rule_id in ('login_failures','password_spray','success_after_failures'):
        details.setdefault('limit', {'login_failures':5,'password_spray':3,'success_after_failures':2}[rule_id])
    title = rule_title(rule_id)
    summary = rule_summary(rule_id, details, subject_str)
    prefix = "[Therefore Security Alert - ESCALATED]" if alert_type == 'escalation' else "[Therefore Security Alert]"
    subject = f"{prefix} {tenant_id}: {title} ({subject_str})"

    f_str = first_ts.astimezone(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')
    l_str = last_ts.astimezone(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')

    link = f"{base_url.rstrip('/')}/t/{tenant_id}/live" if base_url else ""
    if link and finding_id:
        link += f"/findings/{finding_id}"

    body_text = f"""THEREFORE LOG AUDITOR — LIVE SECURITY ALERT
=============================================
Type:     {alert_type.upper()}
Tenant:   {tenant_id}
Severity: {severity.upper()}
Rule:     {title}
Subject:  {subject_str}

Summary:
{summary}

Details:
- First observed: {f_str}
- Last observed:  {l_str}
- Activity count: {details.get('count', 'N/A')}
- Threshold:      {details.get('limit', 'N/A')}
"""
    if details.get('approval_name'):
        body_text += f"- Matched Approval: {details['approval_name']} (exceeded: {details.get('exceeded')})\n"
    body_text += f"- Source IPs: {', '.join(details.get('source_ips', [])) or 'Not available'}\n"
    body_text += f"- Sample document IDs: {', '.join(map(str, details.get('documents', []))) or 'Not available'}\n"
    if link:
        body_text += f"\nReview finding on dashboard:\n{link}\n"

    body_text += """
Coverage: Therefore Console messages only; this is not a complete audit trail or an exact HTTP call count.
Note: Live monitoring detects security anomalies in near real time. Suspected bulk
activity represents unusual volume or patterns and should be investigated in context.
"""

    badge_color = "#dc2626" if severity == 'high' else "#f59e0b"
    esc_pill = '<span style="display:inline-block;padding:2px 8px;font-size:12px;font-weight:600;background:#fee2e2;color:#991b1b;border-radius:4px;margin-left:8px;">ESCALATED</span>' if alert_type == 'escalation' else ''

    html_link = f'<p style="margin:24px 0 16px"><a href="{html.escape(link)}" style="display:inline-block;padding:10px 20px;background:#2563eb;color:#ffffff;text-decoration:none;border-radius:6px;font-weight:600;font-size:14px;">View live finding & evidence →</a></p>' if link else ''

    body_html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:24px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:#0f172a;color:#f8fafc;">
  <div style="max-width:640px;margin:0 auto;background:#1e293b;border:1px solid #334155;border-radius:8px;padding:24px;box-shadow:0 4px 6px rgba(0,0,0,0.3);">
    <div style="border-bottom:1px solid #334155;padding-bottom:16px;margin-bottom:20px;">
      <span style="display:inline-block;padding:3px 10px;font-size:12px;font-weight:700;text-transform:uppercase;background:{badge_color};color:#ffffff;border-radius:4px;letter-spacing:0.5px;">{severity}</span>
      {esc_pill}
      <h1 style="margin:12px 0 4px;font-size:20px;color:#ffffff;font-weight:600;">{html.escape(title)}</h1>
      <div style="font-size:14px;color:#94a3b8;">Tenant: <strong style="color:#e2e8f0;">{html.escape(tenant_id)}</strong> · Subject: <strong style="color:#e2e8f0;">{html.escape(subject_str)}</strong></div>
    </div>

    <div style="background:#0f172a;border-left:4px solid {badge_color};padding:14px 16px;border-radius:4px;margin-bottom:20px;font-size:15px;line-height:1.5;color:#e2e8f0;">
      {html.escape(summary)}
    </div>

    <table style="width:100%;border-collapse:collapse;margin-bottom:20px;font-size:13.5px;">
      <tr>
        <td style="padding:8px 12px;color:#94a3b8;border-bottom:1px solid #334155;width:35%;">First observed</td>
        <td style="padding:8px 12px;color:#f8fafc;border-bottom:1px solid #334155;">{html.escape(f_str)}</td>
      </tr>
      <tr>
        <td style="padding:8px 12px;color:#94a3b8;border-bottom:1px solid #334155;">Last observed</td>
        <td style="padding:8px 12px;color:#f8fafc;border-bottom:1px solid #334155;">{html.escape(l_str)}</td>
      </tr>
      <tr>
        <td style="padding:8px 12px;color:#94a3b8;border-bottom:1px solid #334155;">Activity count</td>
        <td style="padding:8px 12px;color:#f8fafc;border-bottom:1px solid #334155;">{html.escape(str(details.get('count', 'N/A')))}</td>
      </tr>
      <tr>
        <td style="padding:8px 12px;color:#94a3b8;border-bottom:1px solid #334155;">Rule threshold</td>
        <td style="padding:8px 12px;color:#f8fafc;border-bottom:1px solid #334155;">{html.escape(str(details.get('limit', 'N/A')))}</td>
      </tr>
    </table>

    <p style="font-size:13px;color:#94a3b8">Source IPs: {html.escape(', '.join(details.get('source_ips', [])) or 'Not available')}<br>Sample document IDs: {html.escape(', '.join(map(str, details.get('documents', []))) or 'Not available')}</p>
    <p style="font-size:12px;color:#94a3b8">Coverage: Therefore Console messages only; this is not a complete audit trail or an exact HTTP call count.</p>
    {html_link}

    <p style="font-size:12px;color:#64748b;margin-top:24px;border-top:1px solid #334155;padding-top:16px;">
      This alert was generated automatically by the Therefore Log Auditor live security monitor.
      Suspected bulk activity represents unusual volume or patterns and should be investigated in context.
    </p>
  </div>
</body>
</html>"""
    return subject, body_text, body_html


def retry_delay(attempts):
    return min(3600, 30 * 2 ** min(max(attempts - 1, 0), 7))


def dispatch_outbox_batch(conn, settings, batch_size: int = 10, stop=None) -> int:
    """Lock ONE outbox row through SMTP and commit before claiming another.

    Only the dispatcher connection waits for SMTP. Never lock live_state/findings.
    A crash after SMTP acceptance but before commit may still duplicate delivery.
    """
    processed = 0
    for _ in range(batch_size):
        if stop is not None and stop.is_set():
            break
        with conn.transaction(), conn.cursor() as cur:
            cur.execute('''SELECT * FROM live_outbox
                WHERE status IN ('pending','failed') AND attempts < max_attempts
                  AND next_attempt_at <= now()
                ORDER BY next_attempt_at,id FOR UPDATE SKIP LOCKED LIMIT 1''')
            row = cur.fetchone()
            if not row:
                break
            if row['alert_type'] != 'test':
                cur.execute('''SELECT t.enabled AND s.enabled AND s.alerting_enabled AND NOT f.expected
                    AND (s.alerting_enabled_at IS NULL OR %s >= s.alerting_enabled_at) AS permitted
                    FROM tenants t JOIN live_settings s ON s.tenant_id=t.id
                    JOIN live_findings f ON f.tenant_id=t.id AND f.id=%s WHERE t.id=%s''',
                    (row['created_at'], row['finding_id'], row['tenant_id']))
                permission = cur.fetchone()
                if not permission or not permission['permitted']:
                    cur.execute("UPDATE live_outbox SET status='cancelled',last_error=%s WHERE id=%s",
                                ('Notifications/collection disabled or finding marked expected.', row['id']))
                    processed += 1
                    continue
            attempts = row['attempts'] + 1
            error = None
            try:
                smtp = config.load_smtp(conn) or (settings.smtp if settings else {})
            except Exception as exc:
                smtp = {}
                error = 'SMTP configuration: ' + type(exc).__name__
            if not smtp.get('host') and error is None:
                error = 'SMTP host is not configured.'
            if error is None:
                try:
                    digest.send_email(smtp, row['recipients'], row['subject'], row['body_text'], row['body_html'])
                except Exception as exc:
                    # SMTP response bodies can contain credentials or message contents.
                    code = getattr(exc, 'smtp_code', None)
                    error = type(exc).__name__ + (f' (SMTP {code})' if isinstance(code, int) else '')
            if error:
                cur.execute('''UPDATE live_outbox SET status='failed',attempts=%s,last_attempt_at=now(),
                    next_attempt_at=now() + %s * interval '1 second',last_error=%s WHERE id=%s''',
                    (attempts, retry_delay(attempts), error, row['id']))
                log.warning('Live alert #%s attempt %s failed: %s', row['id'], attempts, error)
            else:
                cur.execute('''UPDATE live_outbox SET status='sent',attempts=%s,sent_at=now(),
                    last_attempt_at=now(),last_error=NULL WHERE id=%s''', (attempts, row['id']))
            processed += 1
    return processed
