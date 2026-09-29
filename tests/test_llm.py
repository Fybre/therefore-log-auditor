import pytest

from auditor.llm import LLMError, Redactor, TRIAGE_SCHEMA, _extract_json, _redact_obj, _validate


def test_redactor_round_trip():
    rd = Redactor()
    rd.user("admin"); rd.ip("77.98.171.55")
    t = rd.text("admin used the administrator console from 77.98.171.55")
    assert t == "user_1 used the administrator console from ip_1"
    assert rd.restore(t) == "admin used the administrator console from 77.98.171.55"


def test_redactor_handles_backslash_values():
    """Regression: Therefore SERVER values look like 'AD\\aueapp00'. A real value with a
    backslash used to break restore()'s re.sub, which treated it as a replacement template
    (e.g. '\\a' looks like a regex group escape) instead of a literal string."""
    rd = Redactor()
    rd.host(r"AD\aueapp00")
    t = rd.text(r"restart on AD\aueapp00 at 09:00")
    assert t == "restart on host_1 at 09:00"
    assert rd.restore(t) == r"restart on AD\aueapp00 at 09:00"


def test_redact_details():
    rd = Redactor()
    out = _redact_obj({"user": "bob", "ips": ["1.2.3.4"], "note": "bob again"}, rd)
    assert out == {"user": "user_1", "ips": ["ip_1"], "note": "user_1 again"}


def test_validate():
    ok = {"verdict": "benign", "severity": "low", "confidence": 0.5, "explanation": "x", "recommended_actions": []}
    assert _validate(_extract_json("```json\n" + str(ok).replace("'", '"') + "\n```"), TRIAGE_SCHEMA)["verdict"] == "benign"
    with pytest.raises(LLMError):
        _validate({**ok, "severity": "critical"}, TRIAGE_SCHEMA)
