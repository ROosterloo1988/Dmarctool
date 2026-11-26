"""E-mail notifications.

Detection (every run of the ``alerts`` job):
- DNS: a new error or warning in the latest DNS check; resolved problems are reported too.
  New *errors* are sent immediately, everything else goes into the daily digest.
- New unknown sender: a source seen for the first time in the last 7 days, not recognised and
  not classified as legitimate/abuse, with at least ``notify.new_source_min_messages`` messages.
- Pass-rate drop: DMARC pass rate of the last 7 days (excluding sources marked as abuse) is at
  least ``notify.pass_drop_points`` lower than the 7 days before (re-notified at most weekly).

Every problem is reported once (``alert_state``) until it is resolved. Mails are sent through
Microsoft Graph from the DMARC mailbox (Mail.Send).
"""

from __future__ import annotations

import html
import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from dmarc.appsettings import NotifyConfig, mailbox_config, notify_config
from dmarc.config import Settings, get_settings
from dmarc.db import models as m
from dmarc.dnscheck.run import latest_check
from dmarc.graph import GraphMailbox, GraphNotConfigured

log = logging.getLogger(__name__)
NEW_SOURCE_WINDOW_DAYS = 7
PASS_WINDOW_DAYS = 7
DIGEST_KEY = "_digest"


# --------------------------------------------------------------------------------------
# State helpers
# --------------------------------------------------------------------------------------

def _state(session: Session, domain: str, key: str) -> m.AlertState | None:
    return session.scalars(select(m.AlertState).where(m.AlertState.domain == domain, m.AlertState.key == key)).one_or_none()


def _open(session: Session, domain: str, key: str, now: datetime) -> bool:
    """Mark ``key`` as open. Returns True when this is new (not already open)."""
    st = _state(session, domain, key)
    if st is None:
        session.add(m.AlertState(domain=domain, key=key, status="open", first_seen=now, last_event_at=now))
        session.flush()
        return True
    if st.status == "open":
        return False
    st.status, st.resolved_at, st.last_event_at = "open", None, now
    return True


def _event(session: Session, domain: str, kind: str, severity: str, key: str, title: str, text: str | None,
           link: str | None, immediate: bool, now: datetime) -> m.AlertEvent:
    ev = m.AlertEvent(domain=domain, kind=kind, severity=severity, key=key, title=title, text=text, link=link,
                      immediate=immediate, created_at=now)
    session.add(ev)
    return ev


def _finding_key(f: dict[str, Any]) -> str:
    detail = f.get("detail") or {}
    extra = detail.get("selector") or detail.get("destination") or detail.get("term") or detail.get("tag") or ""
    return f"dns:{f['code']}" + (f":{extra}" if extra else "")


# --------------------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------------------

def detect(session: Session, cfg: NotifyConfig, settings: Settings, now: datetime) -> int:
    created = 0
    base = settings.public_url.rstrip("/")
    for d in session.scalars(select(m.Domain).where(m.Domain.active.is_(True))):
        created += _detect_dns(session, d.name, base, now)
        created += _detect_new_sources(session, d.name, cfg, base, now)
        created += _detect_pass_drop(session, d.name, cfg, base, now)
    session.flush()
    return created


def _detect_dns(session: Session, domain: str, base: str, now: datetime) -> int:
    check = latest_check(session, domain)
    if check is None:
        return 0
    created = 0
    current: dict[str, dict] = {}
    for f in check.findings:
        if f["severity"] in ("error", "warning"):
            current.setdefault(_finding_key(f), f)
    for key, f in current.items():
        if _open(session, domain, key, now):
            is_error = f["severity"] == "error"
            text = f["message"] + (f"\nFix: {f['fix']}" if f.get("fix") else "")
            _event(session, domain, "dns", "critical" if is_error else "warning", key,
                   f"DNS {'problem' if is_error else 'warning'} for {domain}: {f['message']}", text,
                   f"{base}/dns", immediate=is_error, now=now)
            created += 1
    open_dns = session.scalars(select(m.AlertState).where(
        m.AlertState.domain == domain, m.AlertState.status == "open", m.AlertState.key.like("dns:%")))
    for st in open_dns:
        if st.key not in current:
            st.status, st.resolved_at, st.last_event_at = "resolved", now, now
            _event(session, domain, "dns_resolved", "info", st.key, f"Resolved for {domain}: {st.key[4:]}", None,
                   f"{base}/dns", immediate=False, now=now)
            created += 1
    return created


def _detect_new_sources(session: Session, domain: str, cfg: NotifyConfig, base: str, now: datetime) -> int:
    ds = m.DailyStat
    since = (now - timedelta(days=NEW_SOURCE_WINDOW_DAYS)).date()
    rows = session.execute(
        select(ds.source_key, func.max(ds.source_name), func.min(ds.day), func.sum(ds.messages), func.sum(ds.dmarc_pass))
        .where(ds.domain == domain, ds.source_key != "pending").group_by(ds.source_key)
        .having(func.min(ds.day) >= since)).all()
    classified = set(session.scalars(select(m.SourceClassification.source_key).where(
        m.SourceClassification.domain == domain, m.SourceClassification.status.in_(["legit", "abuse"]))))
    created = 0
    for key, name, first_day, messages, passed in rows:
        messages, passed = int(messages), int(passed)
        if key.startswith("sender:") or key in classified or messages < cfg.new_source_min_messages:
            continue
        state_key = f"source:{key}"
        if _state(session, domain, state_key) is not None:
            continue  # reported before: never again
        _open(session, domain, state_key, now)
        pct = round(100 * passed / messages, 1) if messages else 0
        _event(session, domain, "new_source", "warning", state_key,
               f"New unknown sender for {domain}: {name or key}",
               f"{messages:,} messages since {first_day:%d %b %Y}, {pct}% passed DMARC. "
               "If this is a service you use, mark it as legitimate and set up SPF/DKIM; otherwise it is spoofing.",
               f"{base}/sources", immediate=False, now=now)
        created += 1
    return created


def _pass_rate(session: Session, domain: str, start, end) -> tuple[int, int]:
    ds = m.DailyStat
    abuse = select(m.SourceClassification.source_key).where(
        m.SourceClassification.domain == domain, m.SourceClassification.status == "abuse")
    msgs, passed = session.execute(
        select(func.coalesce(func.sum(ds.messages), 0), func.coalesce(func.sum(ds.dmarc_pass), 0))
        .where(ds.domain == domain, ds.day >= start, ds.day < end, ds.source_key.not_in(abuse))).one()
    return int(msgs), int(passed)


def _detect_pass_drop(session: Session, domain: str, cfg: NotifyConfig, base: str, now: datetime) -> int:
    today = now.date()
    split = today - timedelta(days=PASS_WINDOW_DAYS - 1)  # current window: the last 7 days including today
    cur = _pass_rate(session, domain, split, today + timedelta(days=1))
    prev = _pass_rate(session, domain, split - timedelta(days=PASS_WINDOW_DAYS), split)
    if cur[0] < cfg.new_source_min_messages or prev[0] < cfg.new_source_min_messages:
        return 0
    cur_pct, prev_pct = 100 * cur[1] / cur[0], 100 * prev[1] / prev[0]
    st = _state(session, domain, "passrate")
    if prev_pct - cur_pct < cfg.pass_drop_points:
        if st and st.status == "open":
            st.status, st.resolved_at = "resolved", now
        return 0
    if st and st.status == "open" and st.last_event_at > now - timedelta(days=7):
        return 0
    if st is None:
        session.add(m.AlertState(domain=domain, key="passrate", status="open", first_seen=now, last_event_at=now))
    else:
        st.status, st.last_event_at, st.resolved_at = "open", now, None
    _event(session, domain, "pass_drop", "warning", "passrate",
           f"DMARC pass rate for {domain} dropped from {prev_pct:.1f}% to {cur_pct:.1f}%",
           f"Last {PASS_WINDOW_DAYS} days compared with the {PASS_WINDOW_DAYS} days before "
           f"({cur[0]:,} vs {prev[0]:,} messages). Check the sending sources for a service that started failing.",
           f"{base}/", immediate=False, now=now)
    return 1


# --------------------------------------------------------------------------------------
# Delivery
# --------------------------------------------------------------------------------------

SEVERITY_LABEL = {"critical": "Action required", "warning": "Warning", "info": "Info"}
SEVERITY_COLOR = {"critical": "#b42324", "warning": "#8a5a00", "info": "#1757ac"}


def render(events: list[m.AlertEvent], digest: bool, base: str) -> tuple[str, str, str]:
    """(subject, html, text) for a set of events. All dynamic values are HTML-escaped."""
    crit = sum(1 for e in events if e.severity == "critical")
    if digest:
        subject = f"DMARC daily summary: {len(events)} item(s)" + (f", {crit} need action" if crit else "")
    else:
        subject = events[0].title if len(events) == 1 else f"DMARC: {len(events)} problems need action"
    subject = subject[:250]
    order = {"critical": 0, "warning": 1, "info": 2}
    events = sorted(events, key=lambda e: (order.get(e.severity, 9), e.domain, e.created_at))
    rows, text_lines = [], []
    for e in events:
        body = html.escape(e.text or "").replace("\n", "<br>")
        link = f'<br><a href="{html.escape(e.link, quote=True)}">Open in the DMARC portal</a>' if e.link else ""
        rows.append(
            f'<tr><td style="padding:10px 0;border-bottom:1px solid #e5e7eb">'
            f'<div style="font-size:12px;font-weight:600;color:{SEVERITY_COLOR.get(e.severity, "#333")}">'
            f'{SEVERITY_LABEL.get(e.severity, e.severity)} · {html.escape(e.domain)}</div>'
            f'<div style="font-weight:600;margin:2px 0">{html.escape(e.title)}</div>'
            f'<div style="color:#444">{body}{link}</div></td></tr>')
        text_lines.append(f"[{SEVERITY_LABEL.get(e.severity, e.severity)}] {e.title}\n{e.text or ''}\n{e.link or ''}\n")
    intro = ("Summary of DMARC changes since the last summary." if digest
             else "The DMARC portal found a problem that needs attention.")
    html_body = (
        '<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#191919;max-width:680px">'
        f'<p>{intro}</p><table style="width:100%;border-collapse:collapse">{"".join(rows)}</table>'
        f'<p style="color:#666;font-size:12px">Sent by the DMARC portal ({html.escape(base)}). '
        'Change recipients or thresholds under Settings → Notifications.</p></div>')
    text_body = intro + "\n\n" + "\n".join(text_lines) + f"\nSent by the DMARC portal ({base})."
    return subject, html_body, text_body


def graph_message(subject: str, html_body: str, recipients: list[str]) -> dict[str, Any]:
    return {"subject": subject, "body": {"contentType": "HTML", "content": html_body},
            "toRecipients": [{"emailAddress": {"address": r}} for r in recipients]}


MailboxFactory = Callable[[str], GraphMailbox]


def send(session: Session, events: list[m.AlertEvent], digest: bool, recipients: list[str],
         mailbox_factory: MailboxFactory, settings: Settings, now: datetime) -> None:
    address = mailbox_config(session, settings).address
    if not address:
        raise GraphNotConfigured("no mailbox address configured to send from")
    subject, html_body, _ = render(events, digest, settings.public_url.rstrip("/"))
    client = mailbox_factory(address)
    try:
        client.send_mail(graph_message(subject, html_body, recipients))
    finally:
        client.close()
    for e in events:
        e.sent_at, e.send_error = now, None


def run_alerts(session: Session, mailbox_factory: MailboxFactory, settings: Settings | None = None,
               now: datetime | None = None) -> dict[str, Any]:
    s = settings or get_settings()
    now = now or datetime.now(UTC)
    cfg = notify_config(session, s)
    created = detect(session, cfg, s, now)
    result: dict[str, Any] = {"created": created, "immediate_sent": 0, "digest_sent": 0}
    if not cfg.enabled or not cfg.recipients:
        result["skipped"] = "notifications disabled or no recipients"
        session.commit()
        return result

    unsent = session.scalars(select(m.AlertEvent).where(m.AlertEvent.sent_at.is_(None))
                             .order_by(m.AlertEvent.created_at)).all()
    immediate = [e for e in unsent if e.immediate]
    if immediate:
        _try_send(session, immediate, False, cfg, mailbox_factory, s, now, result, "immediate_sent")

    digest_state = _state(session, "*", DIGEST_KEY)
    digest_due = now.hour >= cfg.digest_hour_utc and (digest_state is None or digest_state.last_event_at.date() < now.date())
    pending = [e for e in unsent if not e.immediate and e.sent_at is None]
    if digest_due:
        if pending:
            _try_send(session, pending, True, cfg, mailbox_factory, s, now, result, "digest_sent")
        if not pending or result["digest_sent"]:  # on failure: retry on the next run
            if digest_state is None:
                session.add(m.AlertState(domain="*", key=DIGEST_KEY, status="open", first_seen=now, last_event_at=now))
            else:
                digest_state.last_event_at = now
    session.commit()
    return result


def _try_send(session, events, digest, cfg, factory, s, now, result, counter) -> None:
    try:
        send(session, events, digest, cfg.recipients, factory, s, now)
        result[counter] = len(events)
    except Exception as exc:  # recorded; retried on the next run
        log.error("sending notification failed: %s", exc)
        for e in events:
            e.send_error = str(exc)[:1000]
        result.setdefault("errors", []).append(str(exc)[:300])


def send_test(session: Session, mailbox_factory: MailboxFactory, settings: Settings | None = None,
              requested_by: str | None = None, now: datetime | None = None) -> list[str]:
    s = settings or get_settings()
    now = now or datetime.now(UTC)
    cfg = notify_config(session, s)
    if not cfg.recipients:
        raise ValueError("no recipients configured")
    ev = _event(session, "*", "test", "info", "test", "Test notification from the DMARC portal",
                f"This is a test message requested by {requested_by or 'an administrator'}. "
                "If you can read this, notifications work.", s.public_url, immediate=True, now=now)
    session.flush()
    send(session, [ev], False, cfg.recipients, mailbox_factory, s, now)
    session.commit()
    return cfg.recipients

