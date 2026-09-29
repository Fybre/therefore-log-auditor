"""Pure unit tests for rules/engine.py suppression logic - no DB needed."""
import datetime as dt

from auditor.config import Tenant
from auditor.rules.engine import Finding, suppression_for


def _finding(**overrides) -> Finding:
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    base = dict(rule_id="new_entity", dedupe_key="ip:1.2.3.4", title="New IP address: 1.2.3.4",
                severity="low", first_ts=now, last_ts=now, details={"kind": "ip", "value": "1.2.3.4"},
                subject_ips=["1.2.3.4"])
    base.update(overrides)
    return Finding(**base)


def test_muted_kind_suppresses_without_matching_specific_ip():
    """A muted category (rule:kind) suppresses every finding of that kind, not just ones
    whose subject happens to match a known user/IP - this is what lets 'stop flagging new
    IPs for this tenant' work without needing to enumerate every IP in advance."""
    tenant = Tenant(id="t", base_url="https://t.thereforeonline.com",
                    known={"muted_kinds": ["new_entity:ip"]})
    assert suppression_for(_finding(), tenant) == "muted category"


def test_unmuted_kind_not_suppressed():
    tenant = Tenant(id="t", base_url="https://t.thereforeonline.com", known={})
    assert suppression_for(_finding(), tenant) is None


def test_muting_one_kind_does_not_suppress_another():
    tenant = Tenant(id="t", base_url="https://t.thereforeonline.com",
                    known={"muted_kinds": ["new_entity:ip"]})
    user_finding = _finding(rule_id="new_entity", dedupe_key="user:alice", details={"kind": "user"},
                            subject_users=["alice"], subject_ips=[])
    assert suppression_for(user_finding, tenant) is None


def _snooze(**overrides) -> dict:
    base = dict(rule_id="new_entity", since="2025-12-31T00:00:00+00:00",
                until="2026-01-31T00:00:00+00:00", note="onboarding week")
    base.update(overrides)
    return base


def test_snooze_scoped_to_rule_and_user_suppresses_match():
    tenant = Tenant(id="t", base_url="https://t.thereforeonline.com",
                    known={"snoozes": [_snooze(user="alice")]})
    f = _finding(subject_users=["alice"], subject_ips=[])
    assert suppression_for(f, tenant) == "snoozed: onboarding week"


def test_snooze_does_not_suppress_a_different_user():
    tenant = Tenant(id="t", base_url="https://t.thereforeonline.com",
                    known={"snoozes": [_snooze(user="alice")]})
    f = _finding(subject_users=["mallory"], subject_ips=[])
    assert suppression_for(f, tenant) is None


def test_snooze_does_not_suppress_a_different_rule():
    tenant = Tenant(id="t", base_url="https://t.thereforeonline.com",
                    known={"snoozes": [_snooze(rule_id="mass_delete", user="alice")]})
    f = _finding(rule_id="new_entity", subject_users=["alice"], subject_ips=[])
    assert suppression_for(f, tenant) is None


def test_snooze_does_not_suppress_outside_its_time_range():
    tenant = Tenant(id="t", base_url="https://t.thereforeonline.com",
                    known={"snoozes": [_snooze(user="alice", since="2027-01-01T00:00:00+00:00",
                                               until="2027-02-01T00:00:00+00:00")]})
    f = _finding(subject_users=["alice"], subject_ips=[])   # dated 2026-01-01, before the snooze starts
    assert suppression_for(f, tenant) is None


def test_snooze_with_no_scope_suppresses_any_matching_rule():
    """rule_id set but no user/ip means 'suppress this rule entirely for everyone, for now' -
    e.g. a noisy rule under active tuning."""
    tenant = Tenant(id="t", base_url="https://t.thereforeonline.com",
                    known={"snoozes": [_snooze()]})
    f = _finding(subject_users=["anyone"], subject_ips=[])
    assert suppression_for(f, tenant) == "snoozed: onboarding week"
