"""Symmetric encryption for secrets stored in Postgres (tenant Therefore passwords, the SMTP
password) now that tenant/server config lives in the database instead of .env.

Set AUDITOR_ENC_KEY in .env to anything - a passphrase, a UUID, whatever. It doesn't need to be
a "real" Fernet key: any non-empty string that isn't already one is deterministically stretched
into one (see _derive below), so the only real requirement is that it stays the same across
restarts. (A key generated with `Fernet.generate_key()` is also accepted as-is, for anyone who
already has one - it's used directly rather than re-derived, so existing deployments aren't
affected by this.) If AUDITOR_ENC_KEY isn't set at all, a random key is generated for this
process only: everything encrypted this run becomes unreadable after a restart, so this is fine
for a quick local test but not for anything you want to survive a redeploy."""
from __future__ import annotations

import base64
import hashlib
import logging
import os

from cryptography.fernet import Fernet, InvalidToken

log = logging.getLogger(__name__)
_key_cache: bytes | None = None


def _derive(raw: str) -> bytes:
    """Turn any non-empty string into a valid, stable Fernet key. If `raw` already is one, it's
    returned as-is (so a properly generated key keeps working unchanged); otherwise a Fernet key
    is deterministically derived from it, so the same input string always yields the same key."""
    try:
        Fernet(raw.encode())
        return raw.encode()
    except ValueError:
        return base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest())


def enc_key_is_stable() -> bool:
    """True if AUDITOR_ENC_KEY is set - i.e. secrets encrypted now will still be readable after
    a restart. Used to show a dashboard warning before this bites someone the way it silently
    did in production: without a stable key, every restart gets a fresh random one and every
    previously-stored password becomes permanently undecryptable (crypto.decrypt() then just
    logs and returns "", so the symptom is a confusing downstream auth failure, not an obvious
    error at the source)."""
    return bool(os.environ.get("AUDITOR_ENC_KEY"))


def _key() -> bytes:
    global _key_cache
    if _key_cache:
        return _key_cache
    key = os.environ.get("AUDITOR_ENC_KEY")
    if not key:
        log.warning(
            "AUDITOR_ENC_KEY not set - using a random key for this process only. Secrets saved "
            "now (tenant/SMTP passwords) will not be readable after a restart. Set any stable "
            "value in .env."
        )
        key = Fernet.generate_key().decode()
    _key_cache = _derive(key)
    return _key_cache


def encrypt(plaintext: str) -> str:
    if not plaintext:
        return ""
    return Fernet(_key()).encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        return Fernet(_key()).decrypt(token.encode()).decode()
    except InvalidToken:
        log.error("Could not decrypt a stored secret - AUDITOR_ENC_KEY has changed since it was saved.")
        return ""
