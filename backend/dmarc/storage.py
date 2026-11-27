"""Persisting parsed reports. Idempotent: re-importing the same report is a no-op."""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, insert, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from dmarc.config import Settings, get_settings
from dmarc.db import models as m
from dmarc.parsing.alignment import is_aligned
from dmarc.parsing.message import ParsedMessage, parse_email, parse_file
from dmarc.parsing.rua import AggregateReport
from dmarc.parsing.ruf import ForensicReport

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------------------
# Aggregate
# --------------------------------------------------------------------------------------

def save_aggregate(
    session: Session,
    report: AggregateReport,
    raw_xml: bytes | None = None,
    inbound_message_id: int | None = None,
    settings: Settings | None = None,
) -> int | None:
    """Insert a report with its records. Returns the new id, or None if it already existed."""
    s = settings or get_settings()
    stmt = (
        pg_insert(m.AggregateReport)
        .values(
            org_name=report.org_name[:255],
            report_id=report.report_id[:255],
            domain=report.domain,
            email=(report.email or None) and report.email[:255],
            extra_contact_info=report.extra_contact_info,
            date_begin=report.date_begin,
            date_end=report.date_end,
            version=(report.version or None) and report.version[:16],
            generator=(report.generator or None) and report.generator[:255],
            errors=report.errors,
            adkim=report.policy.adkim,
            aspf=report.policy.aspf,
            p=report.policy.p,
            sp=report.policy.sp,
            np=report.policy.np,
            pct=report.policy.pct,
            fo=report.policy.fo,
            testing=report.policy.testing,
            message_count=report.message_count,
            raw_xml_gz=gzip.compress(raw_xml) if (raw_xml and s.rua_store_raw_xml) else None,
            inbound_message_id=inbound_message_id,
        )
        .on_conflict_do_nothing(constraint="uq_aggregate_report_identity")
        .returning(m.AggregateReport.id)
    )
    report_pk = session.execute(stmt).scalar_one_or_none()
    if report_pk is None:
        return None

    if report.records:
        record_rows = [
            {
                "report_id": report_pk,
                "source_ip": r.source_ip,
                "count": r.count,
                "disposition": r.disposition,
                "policy_dkim": r.policy_dkim,
                "policy_spf": r.policy_spf,
                "reasons": r.reasons,
                "header_from": r.header_from,
                "envelope_from": r.envelope_from,
                "envelope_to": r.envelope_to,
                "spf_aligned": r.spf_aligned,
                "dkim_aligned": r.dkim_aligned,
                "dmarc_pass": r.dmarc_pass,
            }
            for r in report.records
        ]
        record_ids = session.execute(
            insert(m.AggregateRecord).returning(m.AggregateRecord.id, sort_by_parameter_order=True),
            record_rows,
        ).scalars().all()

        auth_rows = []
        for rid, r in zip(record_ids, report.records, strict=True):
            for d in r.dkim:
                auth_rows.append({
                    "record_id": rid, "method": "dkim", "domain": d.domain,
                    "selector": d.selector and d.selector[:255], "scope": None,
                    "result": d.result[:16], "human_result": d.human_result,
                    "aligned": d.result == "pass" and is_aligned(d.domain, r.header_from, report.policy.adkim),
                })
            for sp in r.spf:
                auth_rows.append({
                    "record_id": rid, "method": "spf", "domain": sp.domain,
                    "selector": None, "scope": sp.scope and sp.scope[:8],
                    "result": sp.result[:16], "human_result": None,
                    "aligned": sp.result == "pass" and sp.scope in (None, "mfrom")
                    and is_aligned(sp.domain or r.envelope_from, r.header_from, report.policy.aspf),
                })
        if auth_rows:
            session.execute(insert(m.AuthResult), auth_rows)
    return report_pk


# --------------------------------------------------------------------------------------
# Forensic
# --------------------------------------------------------------------------------------

def forensic_fingerprint(r: ForensicReport) -> str:
    key = json.dumps(
        [
            r.report_message_id,
            r.reporter,
            r.source_ip,
            r.arrival_date.isoformat() if r.arrival_date else None,
            r.original_message_id,
            r.reported_domain,
            r.auth_failure,
        ],
        sort_keys=True,
    )
    return hashlib.sha256(key.encode()).hexdigest()


def save_forensic(
    session: Session,
    report: ForensicReport,
    inbound_message_id: int | None = None,
    settings: Settings | None = None,
    now: datetime | None = None,
) -> int | None:
    s = settings or get_settings()
    now = now or datetime.now(UTC)
    stmt = (
        pg_insert(m.ForensicReport)
        .values(
            fingerprint=forensic_fingerprint(report),
            feedback_type=report.feedback_type[:32],
            reporter=report.reporter,
            user_agent=report.user_agent,
            arrival_date=report.arrival_date,
            source_ip=report.source_ip,
            reported_domain=report.reported_domain,
            original_mail_from=report.original_mail_from,
            original_rcpt_to=report.original_rcpt_to,
            auth_failure=report.auth_failure and report.auth_failure[:32],
            delivery_result=report.delivery_result and report.delivery_result[:32],
            authentication_results=report.authentication_results,
            dkim_domain=report.dkim_domain,
            dkim_selector=report.dkim_selector and report.dkim_selector[:255],
            spf_dns=report.spf_dns,
            identity_alignment=report.identity_alignment and report.identity_alignment[:64],
            original_subject=report.original_subject,
            original_from=report.original_from,
            original_to=report.original_to,
            original_message_id=report.original_message_id,
            original_date=report.original_date,
            original_headers=[list(h) for h in report.original_headers],
            original_body=report.original_body if s.ruf_store_body else None,
            feedback_fields=report.feedback_fields,
            inbound_message_id=inbound_message_id,
            expires_at=now + timedelta(days=s.ruf_retention_days),
        )
        .on_conflict_do_nothing(index_elements=["fingerprint"])
        .returning(m.ForensicReport.id)
    )
    return session.execute(stmt).scalar_one_or_none()


# --------------------------------------------------------------------------------------
# Whole-message ingestion
# --------------------------------------------------------------------------------------

@dataclass
class IngestOutcome:
    status: str  # processed | duplicate | partial | failed
    kind: str
    new: int = 0
    duplicate: int = 0
    errors: list[str] = field(default_factory=list)
    inbound_message_id: int | None = None


def _status(parsed: ParsedMessage, new: int, dup: int, errors: list[str]) -> str:
    if new + dup == 0:
        return "failed"
    if errors:
        return "partial"
    return "processed" if new else "duplicate"


def ingest_parsed(
    session: Session,
    parsed: ParsedMessage,
    source: str,
    external_id: str | None = None,
    received_at: datetime | None = None,
    settings: Settings | None = None,
) -> IngestOutcome:
    """Store all reports of one message plus an inbound_message log row.

    Each report is saved in its own savepoint so that one broken report does not
    prevent the others from being stored. The caller commits.
    """
    s = settings or get_settings()
    errors = list(parsed.errors)

    inbound = None
    if external_id:
        inbound = session.execute(
            select(m.InboundMessage).where(m.InboundMessage.external_id == external_id)
        ).scalar_one_or_none()
    if inbound is None:
        inbound = m.InboundMessage(source=source, external_id=external_id, kind=parsed.kind, status="failed", errors=[])
        session.add(inbound)
    inbound.internet_message_id = parsed.message_id and parsed.message_id[:998]
    inbound.subject = parsed.subject
    inbound.sender = parsed.sender
    inbound.received_at = received_at
    inbound.processed_at = datetime.now(UTC)
    inbound.kind = parsed.kind
    session.flush()

    new = dup = 0
    for report, raw in zip(parsed.aggregate, parsed.aggregate_raw, strict=True):
        try:
            with session.begin_nested():
                pk = save_aggregate(session, report, raw, inbound.id, s)
        except SQLAlchemyError as exc:
            log.exception("failed to store aggregate report %s/%s", report.org_name, report.report_id)
            errors.append(f"database error for report {report.org_name}/{report.report_id}: {type(exc).__name__}")
            continue
        if pk is None:
            dup += 1
        else:
            new += 1

    for fr in parsed.forensic:
        try:
            with session.begin_nested():
                pk = save_forensic(session, fr, inbound.id, s)
        except SQLAlchemyError as exc:
            log.exception("failed to store forensic report")
            errors.append(f"database error for forensic report: {type(exc).__name__}")
            continue
        if pk is None:
            dup += 1
        else:
            new += 1

    inbound.reports_new = new
    inbound.reports_duplicate = dup
    inbound.errors = errors
    inbound.status = _status(parsed, new, dup, errors)
    session.flush()
    return IngestOutcome(inbound.status, parsed.kind, new, dup, errors, inbound.id)


def ingest_email(session: Session, raw: bytes, source: str = "graph", external_id: str | None = None,
                 received_at: datetime | None = None, settings: Settings | None = None) -> IngestOutcome:
    s = settings or get_settings()
    try:
        parsed = parse_email(raw, s)
    except Exception as exc:  # never let one message kill the run
        log.exception("unexpected error while parsing message")
        parsed = ParsedMessage(errors=[f"unexpected parser error: {type(exc).__name__}: {exc}"])
    return ingest_parsed(session, parsed, source, external_id, received_at, s)


def ingest_file(session: Session, data: bytes, name: str, settings: Settings | None = None) -> IngestOutcome:
    s = settings or get_settings()
    try:
        parsed = parse_file(data, name, s)
    except Exception as exc:
        log.exception("unexpected error while parsing %s", name)
        parsed = ParsedMessage(errors=[f"unexpected parser error: {type(exc).__name__}: {exc}"])
    if parsed.subject is None:
        parsed.subject = name
    return ingest_parsed(session, parsed, "file", None, None, s)


# --------------------------------------------------------------------------------------
# Retention
# --------------------------------------------------------------------------------------

def purge_expired(session: Session, settings: Settings | None = None, now: datetime | None = None) -> dict[str, int]:
    s = settings or get_settings()
    now = now or datetime.now(UTC)
    ruf = session.execute(delete(m.ForensicReport).where(m.ForensicReport.expires_at < now)).rowcount
    rua = session.execute(
        delete(m.AggregateReport).where(m.AggregateReport.date_end < now - timedelta(days=s.rua_retention_days))
    ).rowcount
    return {"forensic_deleted": ruf or 0, "aggregate_deleted": rua or 0}
