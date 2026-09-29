"""Pure unit tests for link_tokens.py - no DB needed."""
import time

from auditor import link_tokens


def test_round_trips_a_valid_token():
    token = link_tokens.make_token("s3cret", "acme", 42, "acknowledged")
    payload = link_tokens.verify_token("s3cret", token)
    assert payload["t"] == "acme"
    assert payload["f"] == 42
    assert payload["a"] == "acknowledged"
    assert payload["exp"] > time.time()


def test_rejects_wrong_secret():
    token = link_tokens.make_token("s3cret", "acme", 42, "acknowledged")
    assert link_tokens.verify_token("wrong-secret", token) is None


def test_rejects_tampered_payload():
    token = link_tokens.make_token("s3cret", "acme", 42, "false_positive")
    body, _, sig = token.partition(".")
    tampered = f"{body}x.{sig}"   # corrupt the payload, keep the (now invalid) signature
    assert link_tokens.verify_token("s3cret", tampered) is None


def test_rejects_expired_token():
    token = link_tokens.make_token("s3cret", "acme", 42, "acknowledged", ttl_days=-1)
    assert link_tokens.verify_token("s3cret", token) is None


def test_rejects_disallowed_action():
    assert link_tokens.make_token("s3cret", "acme", 42, "resolved") is None   # not in ALLOWED_ACTIONS


def test_no_token_without_a_secret():
    assert link_tokens.make_token("", "acme", 42, "acknowledged") is None


def test_verify_never_raises_on_garbage_input():
    assert link_tokens.verify_token("s3cret", "") is None
    assert link_tokens.verify_token("s3cret", "not-a-real-token") is None
    assert link_tokens.verify_token("s3cret", "..") is None
    assert link_tokens.verify_token("", "whatever.sig") is None
