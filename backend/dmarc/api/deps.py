"""Shared FastAPI dependencies: database session, current user, role checks, audit."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from dmarc.config import Settings
from dmarc.db.models import AuditLog, User


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def get_db(request: Request) -> Iterator[Session]:
    session: Session = request.app.state.sessions()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@dataclass
class CurrentUser:
    id: int
    name: str
    email: str | None
    role: str
    is_local: bool

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def label(self) -> str:
        return self.email or self.name


def current_user(request: Request, db: Session = Depends(get_db)) -> CurrentUser:
    data = request.session.get("user")
    if not data or data.get("exp", 0) < datetime.now(UTC).timestamp():
        request.session.clear()
        raise HTTPException(401, "not signed in")
    user = db.get(User, data["id"])
    if user is None or not user.active:
        request.session.clear()
        raise HTTPException(401, "account disabled")
    return CurrentUser(user.id, user.name or user.email or user.subject, user.email, user.role, user.is_local)


def require_admin(user: CurrentUser = Depends(current_user)) -> CurrentUser:
    if not user.is_admin:
        raise HTTPException(403, "admin role required")
    return user


def audit(db: Session, request: Request, user: str | None, action: str, target: str | None = None, **detail) -> None:
    db.add(AuditLog(user=user, action=action, target=target, detail=detail,
                    ip=request.client.host if request.client else None))


UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def csrf_protect(request: Request) -> None:
    """Double-submit check: unsafe requests must echo the per-session token from /api/me."""
    if request.method in UNSAFE_METHODS:
        import hmac

        token = request.session.get("csrf")
        sent = request.headers.get("x-csrf-token", "")
        if not token or not hmac.compare_digest(token, sent):
            raise HTTPException(403, "missing or invalid CSRF token")
