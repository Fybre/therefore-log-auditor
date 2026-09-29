"""PBKDF2-SHA256 password hashing for local dashboard accounts. Stdlib only (no bcrypt/argon2
dependency) - fine for a small number of local admin accounts. Format:
pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>."""
from __future__ import annotations

import hashlib
import hmac
import secrets

ITERATIONS = 260_000


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(digest.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False
