"""Session-cookie auth against local dashboard accounts (table `web_users`, managed at
/admin/users and via `auditor create-user`). Entra ID/OIDC was considered and explicitly not
wanted for now - local accounts are the intended long-term auth model here, not a placeholder."""
from __future__ import annotations

import os
from dataclasses import dataclass

import psycopg
from starlette.requests import Request
from starlette.responses import RedirectResponse

from .. import passwords

PUBLIC_PATHS = {"/login", "/static", "/review"}   # /review/{token}: one-click links in emails,
                                                   # authenticated by the signed token itself


@dataclass
class User:
    id: int
    username: str


def authenticate(conn: psycopg.Connection, username: str, password: str) -> User | None:
    with conn.cursor() as cur:
        cur.execute("SELECT id, username, password_hash FROM web_users WHERE username=%s AND NOT disabled",
                    (username,))
        row = cur.fetchone()
    if not row or not passwords.verify_password(password, row["password_hash"]):
        return None
    return User(id=row["id"], username=row["username"])


def bootstrap_first_admin(conn: psycopg.Connection) -> None:
    """If no dashboard accounts exist yet, seed one from AUDITOR_WEB_USER/PASSWORD (.env) so
    there's a way to log in at all. Once any account exists, this is a no-op forever - manage
    accounts from /admin/users or `auditor create-user` after that."""
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM web_users")
        if cur.fetchone()["n"] > 0:
            return
    username, password = os.environ.get("AUDITOR_WEB_USER"), os.environ.get("AUDITOR_WEB_PASSWORD")
    if not (username and password):
        import logging
        logging.getLogger(__name__).warning(
            "No dashboard accounts exist and AUDITOR_WEB_USER/PASSWORD are not set - nobody can "
            "log in. Run `auditor create-user <name>` to create one.")
        return
    with conn.cursor() as cur:
        cur.execute("INSERT INTO web_users (username, password_hash) VALUES (%s, %s)",
                    (username, passwords.hash_password(password)))
    conn.commit()


def current_user(request: Request) -> User | None:
    session_user = request.session.get("user")
    if not isinstance(session_user, dict) or "id" not in session_user:
        return None   # missing, or an old-format session (pre-local-accounts) - just log out
    return User(id=session_user["id"], username=session_user["username"])


def session_secret() -> str:
    secret = os.environ.get("AUDITOR_WEB_SECRET")
    if not secret:
        import logging
        import secrets
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
