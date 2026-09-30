"""Pure unit tests for digest.render() and write_and_send() - no DB needed, data is built by
hand to match the shape gather() produces."""
import datetime as dt
from pathlib import Path

from auditor.config import Settings, Tenant
from auditor.digest import SEV_ORDER, render, write_and_send


def _finding(**overrides):
    now = dt.datetime(2026, 1, 1, 9, 0, tzinfo=dt.timezone.utc)
    base = dict(id=1, rule_id="new_entity", title="New user: alice", severity="medium",
                status="open", first_ts=now, last_ts=now, incident_key=None, suppressed_by=None,
                llm_verdict=None, llm_explanation=None, llm_actions=None)
    base.update(overrides)
    return base


def _data(findings, open_counts=None):
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    return {"findings": findings, "freshness": [], "counts": counts,
            "open_counts": open_counts or {s: 0 for s in SEV_ORDER}}


def test_render_without_dashboard_url_has_no_links():
    tenant = Tenant(id="acme", base_url="https://acme.thereforeonline.com", display_tz="UTC")
    subject, md, html_body = render(tenant, _data([_finding()]), None)
    assert "http" not in md
    assert "Open the dashboard" not in html_body


def test_render_with_dashboard_url_links_findings_and_dashboard():
    tenant = Tenant(id="acme", base_url="https://acme.thereforeonline.com", display_tz="UTC")
    subject, md, html_body = render(tenant, _data([_finding(id=42)]), None,
                                    dashboard_url="https://audit.example.com")
    assert "https://audit.example.com/t/acme/findings" in md
    assert "https://audit.example.com/t/acme/findings/42" in md
    assert 'href="https://audit.example.com/t/acme/findings/42"' in html_body
    assert "Open the dashboard" in html_body


def test_render_adds_review_links_when_dashboard_url_and_secret_set():
    tenant = Tenant(id="acme", base_url="https://acme.thereforeonline.com", display_tz="UTC")
    subject, md, html_body = render(tenant, _data([_finding(id=42)]), None,
                                    dashboard_url="https://audit.example.com", review_secret="s3cret")
    assert "/review/" in md
    assert "Mark reviewed" in md and "False positive" in md
    assert "/review/" in html_body
    assert "Mark reviewed" in html_body and "False positive" in html_body


def test_render_omits_review_links_without_a_secret():
    """Without AUDITOR_WEB_SECRET configured, review links can't be signed - omit them rather
    than emit a link that will always show 'invalid or expired'."""
    tenant = Tenant(id="acme", base_url="https://acme.thereforeonline.com", display_tz="UTC")
    subject, md, html_body = render(tenant, _data([_finding(id=42)]), None,
                                    dashboard_url="https://audit.example.com", review_secret="")
    assert "/review/" not in md
    assert "Mark reviewed" not in html_body


def test_render_strips_trailing_slash_from_dashboard_url():
    """Avoids a double slash (.../findings//42) if someone saves the URL with a trailing /."""
    tenant = Tenant(id="acme", base_url="https://acme.thereforeonline.com", display_tz="UTC")
    subject, md, html_body = render(tenant, _data([_finding(id=42)]), None,
                                    dashboard_url="https://audit.example.com/")
    assert "//findings" not in md


def test_render_shows_currently_open_counts_separately_from_todays_changes():
    """The headline number the digest gives is "what changed today" (counts); this is the
    separate "what's still outstanding overall" number (open_counts) - the whole point of
    adding it, since a finding stops appearing in `findings` once it stops changing day to day."""
    tenant = Tenant(id="acme", base_url="https://acme.thereforeonline.com", display_tz="UTC")
    data = _data([], open_counts={"high": 2, "medium": 5, "low": 1, "info": 0})
    subject, md, html_body = render(tenant, data, None)
    assert "Currently open: 2 high, 5 medium, 1 low" in md
    assert "Currently open: 2 high, 5 medium, 1 low" in html_body


def _settings(reports_dir: Path) -> Settings:
    return Settings(database_url="", tenants=[], rules={}, llm_base_url="", llm_api_key="",
                     llm_model="", smtp={"host": "smtp.example.com", "port": 587}, reports_dir=reports_dir)


def test_write_and_send_skips_email_when_only_on_new_and_nothing_changed(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr("auditor.digest.send_email", lambda *a, **k: sent.append(a))
    tenant = Tenant(id="acme", base_url="https://acme.thereforeonline.com", display_tz="UTC",
                     digest={"email_to": ["ops@acme.test"], "only_on_new": True})
    write_and_send(_settings(tmp_path), tenant, "subject", "md", "<html></html>", has_new_findings=False)
    assert sent == []


def test_write_and_send_still_writes_report_when_email_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr("auditor.digest.send_email", lambda *a, **k: None)
    tenant = Tenant(id="acme", base_url="https://acme.thereforeonline.com", display_tz="UTC",
                     digest={"email_to": ["ops@acme.test"], "only_on_new": True})
    path = write_and_send(_settings(tmp_path), tenant, "subject", "md", "<html></html>", has_new_findings=False)
    assert path.exists()
    assert (tmp_path / "acme" / path.with_suffix(".md").name).exists()


def test_write_and_send_emails_when_only_on_new_and_something_changed(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr("auditor.digest.send_email", lambda *a, **k: sent.append(a))
    tenant = Tenant(id="acme", base_url="https://acme.thereforeonline.com", display_tz="UTC",
                     digest={"email_to": ["ops@acme.test"], "only_on_new": True})
    write_and_send(_settings(tmp_path), tenant, "subject", "md", "<html></html>", has_new_findings=True)
    assert len(sent) == 1


def test_write_and_send_emails_regardless_when_only_on_new_not_set(tmp_path, monkeypatch):
    """Default behaviour (only_on_new unset/False) is unchanged: always email if recipients+SMTP
    are configured, whether or not this run had new findings."""
    sent = []
    monkeypatch.setattr("auditor.digest.send_email", lambda *a, **k: sent.append(a))
    tenant = Tenant(id="acme", base_url="https://acme.thereforeonline.com", display_tz="UTC",
                     digest={"email_to": ["ops@acme.test"]})
    write_and_send(_settings(tmp_path), tenant, "subject", "md", "<html></html>", has_new_findings=False)
    assert len(sent) == 1
