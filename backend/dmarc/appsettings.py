"""Runtime settings that admins can change from the management UI.

Values stored in the ``app_setting`` table override the environment defaults from
:class:`dmarc.config.Settings`. Secrets (Graph client secret / certificate) are
deliberately *not* editable here; they only come from the environment.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from dmarc.config import Settings, get_settings
from dmarc.db.models import AppSetting

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class SettingError(ValueError):
    pass


def _email(v: Any) -> str | None:
    if v is None or v == "":
        return None
    v = str(v).strip().lower()
    if not _EMAIL.match(v):
        raise SettingError(f"not a valid e-mail address: {v!r}")
    return v


def _folder(v: Any) -> str:
    v = str(v or "").strip().strip("/")
    if not v or len(v) > 255 or any(not seg.strip() for seg in v.split("/")):
        raise SettingError("folder must be a non-empty name or path like 'Inbox/DMARC'")
    return v


def _email_list(v: Any) -> list[str]:
    if v is None or v == "":
        return []
    items = v if isinstance(v, list) else re.split(r"[,;\s]+", str(v))
    out: list[str] = []
    for item in items:
        item = str(item).strip()
        if not item:
            continue
        addr = _email(item)
        if addr and addr not in out:
            out.append(addr)
    if len(out) > 20:
        raise SettingError("at most 20 recipients")
    return out


def _float_range(lo: float, hi: float) -> Callable[[Any], float]:
    def check(v: Any) -> float:
        try:
            f = float(v)
        except (TypeError, ValueError) as exc:
            raise SettingError(f"not a number: {v!r}") from exc
        if not lo <= f <= hi:
            raise SettingError(f"must be between {lo:g} and {hi:g}")
        return f
    return check


def _int_range(lo: int, hi: int) -> Callable[[Any], int]:
    def check(v: Any) -> int:
        try:
            i = int(v)
        except (TypeError, ValueError) as exc:
            raise SettingError(f"not a number: {v!r}") from exc
        if not lo <= i <= hi:
            raise SettingError(f"must be between {lo} and {hi}")
        return i
    return check


def _bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "on", "ja"):
        return True
    if s in ("0", "false", "no", "off", "nee"):
        return False
    raise SettingError(f"not a boolean: {v!r}")


@dataclass(frozen=True)
class SettingDef:
    key: str
    env_attr: str
    validate: Callable[[Any], Any]
    label: str


DEFINITIONS: dict[str, SettingDef] = {
    d.key: d
    for d in [
        SettingDef("mailbox.address", "mailbox_address", _email, "Shared mailbox address that receives DMARC reports"),
        SettingDef("mailbox.source_folder", "mailbox_source_folder", _folder, "Folder to read reports from"),
        SettingDef("mailbox.processed_folder", "mailbox_processed_folder", _folder, "Folder for processed mail"),
        SettingDef("mailbox.failed_folder", "mailbox_failed_folder", _folder, "Folder for mail that could not be processed"),
        SettingDef("mailbox.poll_minutes", "mailbox_poll_minutes", _int_range(1, 1440), "Fetch interval in minutes"),
        SettingDef("mailbox.batch_size", "mailbox_batch_size", _int_range(1, 1000), "Maximum messages per run"),
        SettingDef("mailbox.enabled", "mailbox_enabled", _bool, "Fetch mail automatically"),
        SettingDef("notify.enabled", "notify_enabled", _bool, "Send e-mail notifications"),
        SettingDef("notify.recipients", "notify_recipients", _email_list, "Recipients of notifications"),
        SettingDef("notify.digest_hour_utc", "notify_digest_hour_utc", _int_range(0, 23),
                   "Hour (UTC) at which the daily summary is sent"),
        SettingDef("notify.new_source_min_messages", "notify_new_source_min_messages", _int_range(1, 10_000_000),
                   "Report a new unknown sender from this many messages"),
        SettingDef("notify.pass_drop_points", "notify_pass_drop_points", _float_range(0.5, 100),
                   "Report a drop of the DMARC pass rate of at least this many percentage points"),
    ]
}


@dataclass(frozen=True)
class MailboxConfig:
    address: str | None
    source_folder: str
    processed_folder: str
    failed_folder: str
    poll_minutes: int
    batch_size: int
    enabled: bool


def get_all(session: Session, settings: Settings | None = None) -> dict[str, dict[str, Any]]:
    """Effective value of every editable setting, plus where it came from."""
    s = settings or get_settings()
    stored = {row.key: row for row in session.scalars(select(AppSetting))}
    out = {}
    for key, d in DEFINITIONS.items():
        row = stored.get(key)
        out[key] = {
            "value": row.value if row is not None else getattr(s, d.env_attr),
            "source": "database" if row is not None else "environment",
            "default": getattr(s, d.env_attr),
            "label": d.label,
            "updated_by": row.updated_by if row is not None else None,
            "updated_at": row.updated_at if row is not None else None,
        }
    return out


def get_value(session: Session, key: str, settings: Settings | None = None) -> Any:
    return get_all(session, settings)[key]["value"]


def set_value(session: Session, key: str, value: Any, user: str | None = None) -> Any:
    d = DEFINITIONS.get(key)
    if d is None:
        raise SettingError(f"unknown setting {key!r}")
    clean = d.validate(value)
    row = session.get(AppSetting, key)
    if row is None:
        session.add(AppSetting(key=key, value=clean, updated_by=user))
    else:
        row.value = clean
        row.updated_by = user
    session.flush()
    return clean


def reset_value(session: Session, key: str) -> None:
    if key not in DEFINITIONS:
        raise SettingError(f"unknown setting {key!r}")
    row = session.get(AppSetting, key)
    if row is not None:
        session.delete(row)
        session.flush()


def mailbox_config(session: Session, settings: Settings | None = None) -> MailboxConfig:
    v = {k: e["value"] for k, e in get_all(session, settings).items()}
    return MailboxConfig(
        address=v["mailbox.address"],
        source_folder=v["mailbox.source_folder"],
        processed_folder=v["mailbox.processed_folder"],
        failed_folder=v["mailbox.failed_folder"],
        poll_minutes=int(v["mailbox.poll_minutes"]),
        batch_size=int(v["mailbox.batch_size"]),
        enabled=bool(v["mailbox.enabled"]),
    )


@dataclass(frozen=True)
class NotifyConfig:
    enabled: bool
    recipients: list[str]
    digest_hour_utc: int
    new_source_min_messages: int
    pass_drop_points: float


def notify_config(session: Session, settings: Settings | None = None) -> NotifyConfig:
    v = {k: e["value"] for k, e in get_all(session, settings).items()}
    return NotifyConfig(
        enabled=bool(v["notify.enabled"]),
        recipients=list(v["notify.recipients"] or []),
        digest_hour_utc=int(v["notify.digest_hour_utc"]),
        new_source_min_messages=int(v["notify.new_source_min_messages"]),
        pass_drop_points=float(v["notify.pass_drop_points"]),
    )
