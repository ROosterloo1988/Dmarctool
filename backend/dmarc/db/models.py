"""Database schema (PostgreSQL)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Domain(Base):
    """Our own domains that are monitored (DNS checks, dashboard)."""

    __tablename__ = "domain"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(253), unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    parked: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class InboundMessage(Base):
    """Every e-mail (or file) we tried to process, including failures, for the UI error view."""

    __tablename__ = "inbound_message"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source: Mapped[str] = mapped_column(String(16))  # 'graph' | 'file'
    external_id: Mapped[str | None] = mapped_column(String(512), unique=True)  # Graph message id
    internet_message_id: Mapped[str | None] = mapped_column(String(998))
    subject: Mapped[str | None] = mapped_column(Text)
    sender: Mapped[str | None] = mapped_column(Text)
    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    processed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    kind: Mapped[str] = mapped_column(String(8))  # 'rua' | 'ruf' | 'none'
    status: Mapped[str] = mapped_column(String(16))  # 'processed' | 'duplicate' | 'partial' | 'failed'
    reports_new: Mapped[int] = mapped_column(Integer, default=0)
    reports_duplicate: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[list[str]] = mapped_column(JSONB, default=list)
    moved_to: Mapped[str | None] = mapped_column(String(255))  # mailbox folder after processing
    move_error: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (Index("ix_inbound_message_status", "status", "processed_at"),)


class AggregateReport(Base):
    __tablename__ = "aggregate_report"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    org_name: Mapped[str] = mapped_column(String(255))
    report_id: Mapped[str] = mapped_column(String(255))
    domain: Mapped[str] = mapped_column(String(253))
    email: Mapped[str | None] = mapped_column(String(255))
    extra_contact_info: Mapped[str | None] = mapped_column(Text)
    date_begin: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    date_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    version: Mapped[str | None] = mapped_column(String(16))
    generator: Mapped[str | None] = mapped_column(String(255))
    errors: Mapped[list[str]] = mapped_column(JSONB, default=list)
    # policy_published
    adkim: Mapped[str] = mapped_column(String(1), default="r")
    aspf: Mapped[str] = mapped_column(String(1), default="r")
    p: Mapped[str | None] = mapped_column(String(16))
    sp: Mapped[str | None] = mapped_column(String(16))
    np: Mapped[str | None] = mapped_column(String(16))
    pct: Mapped[int | None] = mapped_column(SmallInteger)
    fo: Mapped[str | None] = mapped_column(String(32))
    testing: Mapped[str | None] = mapped_column(String(8))
    # bookkeeping
    message_count: Mapped[int] = mapped_column(BigInteger, default=0)
    raw_xml_gz: Mapped[bytes | None] = mapped_column(LargeBinary)
    inbound_message_id: Mapped[int | None] = mapped_column(ForeignKey("inbound_message.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    records: Mapped[list[AggregateRecord]] = relationship(
        back_populates="report", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        UniqueConstraint("org_name", "report_id", "domain", name="uq_aggregate_report_identity"),
        Index("ix_aggregate_report_domain_period", "domain", "date_begin"),
    )


class AggregateRecord(Base):
    __tablename__ = "aggregate_record"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    report_id: Mapped[int] = mapped_column(ForeignKey("aggregate_report.id", ondelete="CASCADE"))
    source_ip: Mapped[str] = mapped_column(INET)
    count: Mapped[int] = mapped_column(BigInteger)
    disposition: Mapped[str | None] = mapped_column(String(16))
    policy_dkim: Mapped[str | None] = mapped_column(String(16))
    policy_spf: Mapped[str | None] = mapped_column(String(16))
    reasons: Mapped[list[dict]] = mapped_column(JSONB, default=list)
    header_from: Mapped[str | None] = mapped_column(String(253))
    envelope_from: Mapped[str | None] = mapped_column(String(253))
    envelope_to: Mapped[str | None] = mapped_column(String(253))
    spf_aligned: Mapped[bool] = mapped_column(Boolean)
    dkim_aligned: Mapped[bool] = mapped_column(Boolean)
    dmarc_pass: Mapped[bool] = mapped_column(Boolean)
    # Filled by the enrichment job: 'sender:<key>', 'asn:<n>' or 'ip:<address>'
    source_key: Mapped[str | None] = mapped_column(String(64))

    report: Mapped[AggregateReport] = relationship(back_populates="records")
    auth_results: Mapped[list[AuthResult]] = relationship(
        back_populates="record", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        Index("ix_aggregate_record_report", "report_id"),
        Index("ix_aggregate_record_source_ip", "source_ip"),
        Index("ix_aggregate_record_header_from", "header_from"),
        Index("ix_aggregate_record_source_key", "source_key"),
    )


class AuthResult(Base):
    """A single SPF or DKIM result reported for a record."""

    __tablename__ = "auth_result"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    record_id: Mapped[int] = mapped_column(ForeignKey("aggregate_record.id", ondelete="CASCADE"))
    method: Mapped[str] = mapped_column(String(4))  # 'spf' | 'dkim'
    domain: Mapped[str | None] = mapped_column(String(253))
    selector: Mapped[str | None] = mapped_column(String(255))  # dkim only
    scope: Mapped[str | None] = mapped_column(String(8))  # spf only: mfrom | helo
    result: Mapped[str] = mapped_column(String(16))
    human_result: Mapped[str | None] = mapped_column(Text)
    aligned: Mapped[bool] = mapped_column(Boolean)

    record: Mapped[AggregateRecord] = relationship(back_populates="auth_results")

    __table_args__ = (
        Index("ix_auth_result_record", "record_id"),
        Index("ix_auth_result_dkim_selector", "domain", "selector"),
    )


class ForensicReport(Base):
    """RUF report. Contains personal data: retention via ``expires_at``; body optional."""

    __tablename__ = "forensic_report"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    feedback_type: Mapped[str] = mapped_column(String(32))
    reporter: Mapped[str | None] = mapped_column(Text)
    user_agent: Mapped[str | None] = mapped_column(Text)
    arrival_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_ip: Mapped[str | None] = mapped_column(INET)
    reported_domain: Mapped[str | None] = mapped_column(String(253))
    original_mail_from: Mapped[str | None] = mapped_column(Text)
    original_rcpt_to: Mapped[list[str]] = mapped_column(JSONB, default=list)
    auth_failure: Mapped[str | None] = mapped_column(String(32))
    delivery_result: Mapped[str | None] = mapped_column(String(32))
    authentication_results: Mapped[str | None] = mapped_column(Text)
    dkim_domain: Mapped[str | None] = mapped_column(String(253))
    dkim_selector: Mapped[str | None] = mapped_column(String(255))
    spf_dns: Mapped[str | None] = mapped_column(Text)
    identity_alignment: Mapped[str | None] = mapped_column(String(64))
    original_subject: Mapped[str | None] = mapped_column(Text)
    original_from: Mapped[str | None] = mapped_column(Text)
    original_to: Mapped[str | None] = mapped_column(Text)
    original_message_id: Mapped[str | None] = mapped_column(Text)
    original_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    original_headers: Mapped[list[list[str]]] = mapped_column(JSONB, default=list)
    original_body: Mapped[bytes | None] = mapped_column(LargeBinary)
    feedback_fields: Mapped[dict] = mapped_column(JSONB, default=dict)
    inbound_message_id: Mapped[int | None] = mapped_column(ForeignKey("inbound_message.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_forensic_report_domain_arrival", "reported_domain", "arrival_date"),
        Index("ix_forensic_report_expires", "expires_at"),
    )


class AppSetting(Base):
    """Runtime settings editable from the management UI (never secrets)."""

    __tablename__ = "app_setting"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[object] = mapped_column(JSONB)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    updated_by: Mapped[str | None] = mapped_column(String(255))


class JobRun(Base):
    """History of background jobs; a row with status 'queued' asks the worker to run a job now."""

    __tablename__ = "job_run"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    job: Mapped[str] = mapped_column(String(32))  # 'fetch' | 'purge' | ...
    status: Mapped[str] = mapped_column(String(16))  # queued | running | ok | error | skipped
    requested_by: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stats: Mapped[dict] = mapped_column(JSONB, default=dict)
    error: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (Index("ix_job_run_job_created", "job", "created_at"),)


class DnsCheck(Base):
    """Result of one DNS check run for one of our domains (history is kept)."""

    __tablename__ = "dns_check"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    domain: Mapped[str] = mapped_column(String(253))
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    result: Mapped[dict] = mapped_column(JSONB)
    findings: Mapped[list[dict]] = mapped_column(JSONB)
    error_count: Mapped[int] = mapped_column(Integer)
    warning_count: Mapped[int] = mapped_column(Integer)

    __table_args__ = (Index("ix_dns_check_domain_time", "domain", "checked_at"),)


class IpInfo(Base):
    """Enrichment of a source IP: reverse DNS, ASN, country, recognised sender."""

    __tablename__ = "ip_info"

    ip: Mapped[str] = mapped_column(INET, primary_key=True)
    ptr: Mapped[str | None] = mapped_column(String(253))
    ptr_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)  # forward-confirmed rDNS
    asn: Mapped[int | None] = mapped_column(BigInteger)
    as_org: Mapped[str | None] = mapped_column(String(255))
    country: Mapped[str | None] = mapped_column(String(2))
    sender_key: Mapped[str | None] = mapped_column(String(64))  # from the PTR/ASN catalog match
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class DailyStat(Base):
    """Daily totals per domain and source. Rebuilt from records; kept after records are purged."""

    __tablename__ = "daily_stat"

    domain: Mapped[str] = mapped_column(String(253), primary_key=True)
    day: Mapped[datetime] = mapped_column(Date, primary_key=True)
    source_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    source_name: Mapped[str | None] = mapped_column(String(255))
    messages: Mapped[int] = mapped_column(BigInteger)
    dmarc_pass: Mapped[int] = mapped_column(BigInteger)
    spf_aligned: Mapped[int] = mapped_column(BigInteger)
    dkim_aligned: Mapped[int] = mapped_column(BigInteger)
    spf_pass: Mapped[int] = mapped_column(BigInteger)
    dkim_pass: Mapped[int] = mapped_column(BigInteger)
    disp_quarantine: Mapped[int] = mapped_column(BigInteger)
    disp_reject: Mapped[int] = mapped_column(BigInteger)
    forwarded: Mapped[int] = mapped_column(BigInteger)


class SourceClassification(Base):
    """Admin's verdict about a sending source for one of our domains."""

    __tablename__ = "source_classification"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(253))
    source_key: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))  # legit | unknown | abuse
    note: Mapped[str | None] = mapped_column(Text)
    updated_by: Mapped[str | None] = mapped_column(String(255))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    __table_args__ = (UniqueConstraint("domain", "source_key", name="uq_source_classification"),)


class User(Base):
    """A person who signed in. Entra ID users are created on first login; roles come from the token."""

    __tablename__ = "app_user"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subject: Mapped[str] = mapped_column(String(255), unique=True)  # 'entra:<tid>:<oid>' or 'local:<username>'
    email: Mapped[str | None] = mapped_column(String(255))
    name: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))  # admin | viewer
    is_local: Mapped[bool] = mapped_column(Boolean, default=False)
    password_hash: Mapped[str | None] = mapped_column(String(255))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    user: Mapped[str | None] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str | None] = mapped_column(String(512))
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)
    ip: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (Index("ix_audit_log_at", "at"),)
