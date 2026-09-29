"""Session-cookie auth for the dashboard.

This is a placeholder identity provider: one admin login from the environment
(AUDITOR_WEB_USER / AUDITOR_WEB_PASSWORD), checked with a constant-time compare and stored in a
signed session cookie. It exists so every route already goes through `current_user()` and every
write already records a real `User.username` - swapping this out for Entra ID/OIDC later means
replacing `authenticate()` and the /login route with an OIDC redirect + callback that populates
`request.session["user"]`, not touching any page or the findings-review code that reads it.
"""
from __future__ import annotations

import hmac
import os
import secrets
from dataclasses import dataclass

from starlette.requests import Request
from starlette.responses import RedirectResponse

PUBLIC_PATHS = {"/login", "/static"}


@dataclass
class User:
    username: str


def authenticate(username: str, password: str) -> User | None:
    exp_user = os.environ.get("AUDITOR_WEB_USER", "")
    exp_pass = os.environ.get("AUDITOR_WEB_PASSWORD", "")
    if not (exp_user and exp_pass):
        return None
    if hmac.compare_digest(username, exp_user) and hmac.compare_digest(password, exp_pass):
        return User(username=username)
    return None


def current_user(request: Request) -> User | None:
    username = request.session.get("user")
    return User(username=username) if username else None


def session_secret() -> str:
    secret = os.environ.get("AUDITOR_WEB_SECRET")
    if not secret:
        import logging
        logging.getLogger(__name__).warning(
            "AUDITOR_WEB_SECRET not set - using a random secret, so sessions will not survive a "
            "restart. Set it in .env for a real deployment.")
        secret = secrets.token_hex(32)
    return secret


class RequireLoginMiddleware:
    """Redirects any unauthenticated request that isn't login/static to /login."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope["path"]
        if any(path == p or path.startswith(p + "/") for p in PUBLIC_PATHS):
            return await self.app(scope, receive, send)
        request = Request(scope, receive)
        if current_user(request) is None:
            response = RedirectResponse(url=f"/login?next={path}", status_code=303)
            return await response(scope, receive, send)
        return await self.app(scope, receive, send)
