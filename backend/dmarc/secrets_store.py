"""Encrypted, write-only storage for secrets entered in the admin portal.

Values are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) using a key derived from
DMARC_SECRET_KEY. The API never returns a stored value; only whether one is set, by whom and
when. If DMARC_SECRET_KEY changes, stored secrets can no longer be decrypted and must be
entered again (the portal shows this).
"""

from __future__ import annotations

import base64
import hashlib
import logging
from datetime import datetime
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from dmarc.config import Settings, get_settings
from dmarc.db.models import SecretSetting

log = logging.getLogger(__name__)

SECRETS = {"graph.client_secret": "Microsoft Graph client secret"}


class SecretStoreError(Exception):
    pass


def _fernet(settings: Settings) -> Fernet:
    if settings.secret_key is None or len(settings.secret_key.get_secret_value()) < 32:
        raise SecretStoreError("DMARC_SECRET_KEY must be set (at least 32 characters) to store secrets")
    digest = hashlib.sha256(b"dmarc-secret-store-v1:" + settings.secret_key.get_secret_value().encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def set_secret(session: Session, key: str, value: str, user: str | None, settings: Settings | None = None) -> None:
    if key not in SECRETS:
        raise SecretStoreError(f"unknown secret {key!r}")
    value = value.strip()
    if not value or len(value) > 2048:
        raise SecretStoreError("secret must be between 1 and 2048 characters")
    token = _fernet(settings or get_settings()).encrypt(value.encode())
    row = session.get(SecretSetting, key)
    if row is None:
        session.add(SecretSetting(key=key, ciphertext=token, updated_by=user))
    else:
        row.ciphertext, row.updated_by = token, user
    session.flush()


def delete_secret(session: Session, key: str) -> bool:
    row = session.get(SecretSetting, key)
    if row is None:
        return False
    session.delete(row)
    session.flush()
    return True


def get_secret(session: Session, key: str, settings: Settings | None = None) -> str | None:
    """Decrypted value for internal use only (never returned by the API)."""
    row = session.get(SecretSetting, key)
    if row is None:
        return None
    try:
        return _fernet(settings or get_settings()).decrypt(row.ciphertext).decode()
    except (InvalidToken, SecretStoreError):
        log.error("stored secret %s cannot be decrypted (was DMARC_SECRET_KEY changed?)", key)
        return None


def secret_status(session: Session, key: str, settings: Settings | None = None) -> dict[str, Any]:
    row = session.get(SecretSetting, key)
    if row is None:
        return {"stored": False, "readable": None, "updated_by": None, "updated_at": None}
    readable = get_secret(session, key, settings) is not None
    updated_at: datetime | None = row.updated_at
    return {"stored": True, "readable": readable, "updated_by": row.updated_by, "updated_at": updated_at}
