"""Symmetric encryption for secrets stored in Postgres (tenant Therefore passwords, the SMTP
password) now that tenant/server config lives in the database instead of .env.

AUDITOR_ENC_KEY must be a stable Fernet key - generate one with
`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
and put it in .env. If it's not set, a random key is generated for this process only: everything
encrypted this run becomes unreadable after a restart, so this is fine for a quick local test but
not for anything you want to survive a redeploy."""
from __future__ import annotations

import logging
import os

from cryptography.fernet import Fernet, InvalidToken

log = logging.getLogger(__name__)
_key_cache: bytes | None = None


def _key() -> bytes:
    global _key_cache
    if _key_cache:
        return _key_cache
    key = os.environ.get("AUDITOR_ENC_KEY")
    if key:
        try:
            Fernet(key.encode())   # validates it's a real 32-byte url-safe base64 key
        except ValueError:
            log.error(
                "AUDITOR_ENC_KEY is set but is not a valid Fernet key (generate one with "
                "`python -c \"from cryptography.fernet import Fernet; "
                "print(Fernet.generate_key().decode())\"`) - falling back to a random key for "
                "this process only."
            )
            key = None
    if not key:
        log.warning(
            "AUDITOR_ENC_KEY not set (or invalid) - using a random key for this process only. "
            "Secrets saved now (tenant/SMTP passwords) will not be readable after a restart. "
            "Set a valid key in .env."
        )
        key = Fernet.generate_key().decode()
    _key_cache = key.encode()
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
