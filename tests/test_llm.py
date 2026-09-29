import pytest

from auditor.llm import LLMError, Redactor, TRIAGE_SCHEMA, _extract_json, _redact_obj, _validate


def test_redactor_round_trip():
    rd = Redactor()
    rd.user("admin"); rd.ip("77.98.171.55")
    t = rd.text("admin used the administrator console from 77.98.171.55")
    assert t == "user_1 used the administrator console from ip_1"
    assert rd.restore(t) == "admin used the administrator console from 77.98.171.55"


def test_redact_details():
    rd = Redactor()
    out = _redact_obj({"user": "bob", "ips": ["1.2.3.4"], "note": "bob again"}, rd)
    assert out == {"user": "user_1", "ips": ["ip_1"], "note": "user_1 again"}


def test_validate():
    ok = {"verdict": "benign", "severity": "low", "confidence": 0.5, "explanation": "x", "recommended_actions": []}
    assert _validate(_extract_json("```json\n" + str(ok).replace("'", '"') + "\n```"), TRIAGE_SCHEMA)["verdict"] == "benign"
    with pytest.raises(LLMError):
        _validate({**ok, "severity": "critical"}, TRIAGE_SCHEMA)
