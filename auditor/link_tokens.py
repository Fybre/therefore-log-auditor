"""Signed, expiring tokens for the one-click review links in digest emails. Deliberately narrow:
the only thing a token can do is set one specific finding to one specific, safe review status
(never anything else), and it expires. No dependency beyond stdlib hmac/base64/json.

Email-safety note: corporate mail gateways and some clients "prefetch" (silently GET) every link
in an email to scan it, which would fire a real action before a human ever saw the message if the
link performed it on GET. So the flow here is: GET shows an unauthenticated confirmation page,
POST (a real click on a button, not a prefetch) performs the action. Two clicks, but safe.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

ALLOWED_ACTIONS = ("acknowledged", "false_positive")
DEFAULT_TTL_DAYS = 30


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def make_token(secret: str, tenant_id: str, finding_id: int, action: str,
                ttl_days: int = DEFAULT_TTL_DAYS) -> str | None:
    if not secret or action not in ALLOWED_ACTIONS:
        return None
    payload = {"t": tenant_id, "f": finding_id, "a": action,
               "exp": int(time.time()) + ttl_days * 86400}
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def verify_token(secret: str, token: str) -> dict | None:
    """Returns the payload dict if the token is well-formed, correctly signed and unexpired;
    None otherwise. Never raises on malformed input."""
    if not secret or not token or "." not in token:
        return None
    body, _, sig = token.partition(".")
    try:
        expected = _b64(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(_unb64(body))
    except Exception:
        return None
    if payload.get("a") not in ALLOWED_ACTIONS:
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    return payload
