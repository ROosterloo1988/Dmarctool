"""Fetch DMARC report mail from the shared mailbox, ingest it and file it away.

Flow per message (oldest first):
  1. download the raw MIME message,
  2. parse + store (idempotent, see dmarc.storage),
  3. commit,
  4. move to the "processed" folder (status processed/duplicate) or the "failed" folder
     (status partial/failed). Mail is never deleted.

If moving fails, the database already holds the result; on the next run the message is
recognised by its Graph id and only the move is retried.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import asdict, dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from dmarc.appsettings import mailbox_config
from dmarc.config import Settings, get_settings
from dmarc.db.models import InboundMessage
from dmarc.graph import GraphError, GraphMailbox, GraphMessage, GraphNotConfigured, MessageTooLarge
from dmarc.parsing.message import ParsedMessage
from dmarc.storage import ingest_email, ingest_parsed

log = logging.getLogger(__name__)

OK_STATUSES = {"processed", "duplicate"}


@dataclass
class FetchStats:
    seen: int = 0
    processed: int = 0
    duplicate: int = 0
    partial: int = 0
    failed: int = 0
    reports_new: int = 0
    moved: int = 0
    move_retried: int = 0
    download_errors: int = 0
    move_errors: int = 0

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


MailboxFactory = Callable[[str], GraphMailbox]


def run_fetch(
    sessions: sessionmaker[Session],
    mailbox_factory: MailboxFactory,
    settings: Settings | None = None,
) -> FetchStats:
    s = settings or get_settings()
    with sessions() as session:
        cfg = mailbox_config(session, s)
    if not cfg.address:
        raise GraphNotConfigured("no mailbox address configured (setting 'mailbox.address')")

    folders = {f.lower() for f in (cfg.source_folder, cfg.processed_folder, cfg.failed_folder)}
    if len(folders) != 3:
        raise GraphError("source, processed and failed folders must all be different")

    stats = FetchStats()
    client = mailbox_factory(cfg.address)
    try:
        source_id = client.resolve_folder(cfg.source_folder)
        targets = {
            True: (cfg.processed_folder, client.resolve_folder(cfg.processed_folder, create=True)),
            False: (cfg.failed_folder, client.resolve_folder(cfg.failed_folder, create=True)),
        }
        for msg in client.list_messages(source_id, cfg.batch_size):
            stats.seen += 1
            try:
                _handle_message(sessions, client, msg, targets, stats, s)
            except GraphNotConfigured:
                raise
            except Exception:  # one bad message must never stop the run
                log.exception("unexpected error handling message %s", msg.id)
                stats.failed += 1
    finally:
        client.close()
    log.info("fetch finished: %s", stats.as_dict())
    return stats


def _handle_message(
    sessions: sessionmaker[Session],
    client: GraphMailbox,
    msg: GraphMessage,
    targets: dict[bool, tuple[str, str]],
    stats: FetchStats,
    s: Settings,
) -> None:
    with sessions() as session:
        existing = session.scalars(select(InboundMessage).where(InboundMessage.external_id == msg.id)).one_or_none()

        if existing is not None and existing.moved_to is None and existing.status in OK_STATUSES | {"partial", "failed"}:
            # Already ingested in an earlier run; only the move failed.
            ok = existing.status in OK_STATUSES
            stats.move_retried += 1
            _move(session, client, existing, msg.id, targets[ok], stats)
            return

        try:
            raw = client.get_mime(msg.id)
        except MessageTooLarge as exc:
            outcome = ingest_parsed(
                session, ParsedMessage(subject=msg.subject, sender=msg.sender, message_id=msg.internet_message_id,
                                       errors=[str(exc)]),
                "graph", msg.id, msg.received_at, s)
        except GraphError as exc:
            # Transient (network, throttling after retries): leave the mail where it is.
            log.warning("download of %s failed: %s", msg.id, exc)
            stats.download_errors += 1
            return
        else:
            outcome = ingest_email(session, raw, "graph", msg.id, msg.received_at, s)

        session.commit()
        setattr(stats, outcome.status, getattr(stats, outcome.status) + 1)
        stats.reports_new += outcome.new
        inbound = session.get(InboundMessage, outcome.inbound_message_id)
        if inbound.subject is None:
            inbound.subject = msg.subject
        if inbound.sender is None:
            inbound.sender = msg.sender
        _move(session, client, inbound, msg.id, targets[outcome.status in OK_STATUSES], stats)


def _move(session: Session, client: GraphMailbox, inbound: InboundMessage, message_id: str,
          target: tuple[str, str], stats: FetchStats) -> None:
    name, folder_id = target
    try:
        client.move(message_id, folder_id)
    except GraphError as exc:
        log.warning("moving %s to %s failed: %s", message_id, name, exc)
        inbound.move_error = str(exc)[:2000]
        stats.move_errors += 1
    else:
        inbound.moved_to = name
        inbound.move_error = None
        stats.moved += 1
    session.commit()
