"""Sign-in: Microsoft Entra ID (OIDC, authorization code + PKCE) and optional local break-glass accounts."""

from __future__ import annotations

import logging
import secrets
import time
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from dmarc.config import Settings
from dmarc.db.models import User

from .deps import CurrentUser, audit, csrf_protect, current_user, get_db, get_settings_dep

log = logging.getLogger(__name__)
router = APIRouter()
hasher = PasswordHasher()
_DUMMY_HASH = hasher.hash("dummy-password-for-timing")


def hash_password(password: str) -> str:
    if len(password) < 14:
        raise ValueError("password must be at least 14 characters")
    return hasher.hash(password)


# --------------------------------------------------------------------------------------
# Session helpers
# --------------------------------------------------------------------------------------

def start_session(request: Request, user: User, settings: Settings) -> None:
    request.session.clear()  # new session id/content after login (no fixation)
    request.session["user"] = {
        "id": user.id,
        "exp": (datetime.now(UTC) + timedelta(hours=settings.session_hours)).timestamp(),
    }
    request.session["csrf"] = secrets.token_urlsafe(32)


def oidc_enabled(settings: Settings) -> bool:
    return bool(settings.oidc_client_id and settings.oidc_client_secret and (settings.oidc_tenant_id or settings.graph_tenant_id))


def oidc_client(request: Request):
    return request.app.state.oauth.create_client("entra") if request.app.state.oauth else None


def setup_oauth(settings: Settings):
    if not oidc_enabled(settings):
        return None
    from authlib.integrations.starlette_client import OAuth

    tenant = settings.oidc_tenant_id or settings.graph_tenant_id
    oauth = OAuth()
    oauth.register(
        name="entra",
        server_metadata_url=f"{settings.graph_authority_host.rstrip('/')}/{tenant}/v2.0/.well-known/openid-configuration",
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret.get_secret_value(),
        client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"},
    )
    return oauth


def role_from_claims(claims: dict, settings: Settings) -> str | None:
    roles = claims.get("roles") or []
    if settings.oidc_admin_role in roles:
        return "admin"
    if settings.oidc_viewer_role in roles:
        return "viewer"
    return None


def upsert_entra_user(db: Session, claims: dict, settings: Settings) -> User:
    tenant = settings.oidc_tenant_id or settings.graph_tenant_id
    if claims.get("tid") != tenant:
        raise HTTPException(403, "account from another tenant")
    role = role_from_claims(claims, settings)
    if role is None:
        raise HTTPException(403, "no DMARC role assigned to this account")
    subject = f"entra:{claims['tid']}:{claims['oid']}"
    user = db.scalars(select(User).where(User.subject == subject)).one_or_none()
    if user is None:
        user = User(subject=subject, role=role, is_local=False, active=True, failed_logins=0)
        db.add(user)
    if not user.active:
        raise HTTPException(403, "account disabled in the DMARC portal")
    user.email = (claims.get("email") or claims.get("preferred_username") or "")[:255] or None
    user.name = (claims.get("name") or "")[:255] or None
    user.role = role  # always follow the current app role assignment in Entra ID
    user.last_login = datetime.now(UTC)
    db.flush()
    return user


# --------------------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------------------

@router.get("/auth/config")
def auth_config(settings: Settings = Depends(get_settings_dep)):
    return {"oidc": oidc_enabled(settings), "local": settings.local_login_enabled}


@router.get("/auth/login")
async def login(request: Request, settings: Settings = Depends(get_settings_dep)):
    client = oidc_client(request)
    if client is None:
        raise HTTPException(404, "SSO is not configured")
    return await client.authorize_redirect(request, f"{settings.public_url.rstrip('/')}/auth/callback")


@router.get("/auth/callback")
async def callback(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings_dep)):
    client = oidc_client(request)
    if client is None:
        raise HTTPException(404, "SSO is not configured")
    if "error" in request.query_params:
        log.warning("Entra ID sign-in error: %s", request.query_params.get("error_description"))
        return RedirectResponse("/login?error=signin_failed", status_code=303)
    try:
        token = await client.authorize_access_token(request)
    except Exception as exc:  # state mismatch, invalid token, ...
        log.warning("OIDC callback failed: %s", exc)
        return RedirectResponse("/login?error=signin_failed", status_code=303)
    claims = token.get("userinfo") or {}
    try:
        user = upsert_entra_user(db, claims, settings)
    except HTTPException as exc:
        audit(db, request, claims.get("preferred_username"), "login_denied", detail=exc.detail)
        db.commit()
        return RedirectResponse("/login?error=no_access", status_code=303)
    start_session(request, user, settings)
    audit(db, request, user.email, "login", via="entra")
    return RedirectResponse("/", status_code=303)


class LocalLogin(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=512)


class _RateLimiter:
    """Per-IP sliding window, in memory (single api process)."""

    def __init__(self, limit: int = 10, window: float = 300):
        self.limit, self.window = limit, window
        self.hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        q = self.hits[key]
        while q and q[0] < now - self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True


login_limiter = _RateLimiter()


@router.post("/auth/local-login")
def local_login(body: LocalLogin, request: Request, db: Session = Depends(get_db),
                settings: Settings = Depends(get_settings_dep)):
    if not settings.local_login_enabled:
        raise HTTPException(404, "local login is disabled")
    if not request.headers.get("content-type", "").startswith("application/json"):
        raise HTTPException(415, "JSON required")  # blocks cross-site HTML form posts (login CSRF)
    ip = request.client.host if request.client else "?"
    if not login_limiter.allow(ip):
        raise HTTPException(429, "too many attempts, try again later")
    user = db.scalars(select(User).where(User.subject == f"local:{body.username.lower()}")).one_or_none()
    now = datetime.now(UTC)
    if user is None or not user.active or not user.password_hash:
        try:
            hasher.verify(_DUMMY_HASH, body.password)  # same timing as a real check
        except VerificationError:
            pass
        audit(db, request, body.username, "login_failed", via="local")
        db.commit()
        raise HTTPException(401, "invalid username or password")
    if user.locked_until and user.locked_until > now:
        raise HTTPException(423, "account temporarily locked")
    try:
        hasher.verify(user.password_hash, body.password)
    except (VerificationError, InvalidHashError):
        user.failed_logins += 1
        if user.failed_logins >= settings.login_max_failures:
            user.locked_until = now + timedelta(minutes=settings.login_lockout_minutes)
            user.failed_logins = 0
        audit(db, request, body.username, "login_failed", via="local")
        db.commit()
        raise HTTPException(401, "invalid username or password") from None
    if hasher.check_needs_rehash(user.password_hash):
        user.password_hash = hasher.hash(body.password)
    user.failed_logins, user.locked_until, user.last_login = 0, None, now
    start_session(request, user, settings)
    audit(db, request, user.name, "login", via="local")
    return {"ok": True}


@router.post("/auth/logout", dependencies=[Depends(csrf_protect)])
def logout(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings_dep)):
    data = request.session.get("user")
    if data:
        user = db.get(User, data["id"])
        audit(db, request, user.email or user.name if user else None, "logout")
        is_local = bool(user and user.is_local)
    else:
        is_local = True
    request.session.clear()
    if not is_local and oidc_enabled(settings):
        tenant = settings.oidc_tenant_id or settings.graph_tenant_id
        url = (f"{settings.graph_authority_host.rstrip('/')}/{tenant}/oauth2/v2.0/logout?"
               + urlencode({"post_logout_redirect_uri": f"{settings.public_url.rstrip('/')}/auth/logged-out"}))
        return {"redirect": url}
    return {"redirect": "/login?logged_out=1"}


@router.get("/auth/logged-out")
def logged_out(request: Request):
    request.session.clear()
    return RedirectResponse("/login?logged_out=1", status_code=303)


@router.get("/api/me")
def me(request: Request, user: CurrentUser = Depends(current_user)):
    return {"id": user.id, "name": user.name, "email": user.email, "role": user.role,
            "is_local": user.is_local, "csrf": request.session.get("csrf")}
