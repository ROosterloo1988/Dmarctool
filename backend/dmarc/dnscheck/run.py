"""Run all DNS checks for a domain and store the result."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from dmarc.config import Settings, get_settings
from dmarc.db import models as m
from dmarc.dnscheck.dkim import check_selector
from dmarc.dnscheck.dmarc_record import check_dmarc
from dmarc.dnscheck.findings import Finding, sort_findings
from dmarc.dnscheck.resolver import DnsLookupError, DnsPythonResolver, Resolver
from dmarc.dnscheck.spf import check_spf

MAX_SELECTORS = 25


def check_domain(domain: str, resolver: Resolver, selectors: list[tuple[str, str]] | None = None,
                 parked: bool = False) -> dict[str, Any]:
    """``selectors``: (signing domain, selector) pairs, the signing domain being ``domain`` or a subdomain."""
    findings: list[Finding] = []
    dmarc, f = check_dmarc(domain, resolver)
    findings += f
    spf, f = check_spf(domain, resolver)
    findings += f

    dkim = []
    if selectors:
        for sign_domain, sel in selectors[:MAX_SELECTORS]:
            info, f = check_selector(sign_domain, sel, resolver)
            dkim.append(info)
            findings += f
    elif not parked:
        findings.append(Finding("dkim", "info", "dkim.no_selectors",
                                "No DKIM selectors for this domain appear in the reports yet.",
                                "Set up DKIM signing with your own domain for every sending service."))

    if parked:
        findings += _parked_checks(domain, dmarc, spf, resolver)

    return {
        "domain": domain,
        "parked": parked,
        "dmarc": dmarc,
        "spf": spf.as_dict(),
        "dkim": dkim,
        "findings": [x.as_dict() for x in sort_findings(findings)],
    }


def _parked_checks(domain, dmarc, spf, resolver) -> list[Finding]:
    out = []
    if spf.records and spf.records[0].split() != ["v=spf1", "-all"]:
        out.append(Finding("parked", "warning", "parked.spf",
                           "This domain does not send mail, but its SPF record allows senders.",
                           f'Set the SPF record of {domain} to "v=spf1 -all".'))
    if dmarc.get("effective_policy") != "reject":
        out.append(Finding("parked", "warning", "parked.dmarc",
                           "A domain that does not send mail should have p=reject.",
                           f'Set _dmarc.{domain} to "v=DMARC1; p=reject; rua=mailto:<report address>".'))
    try:
        mx = resolver.mx(domain)
    except DnsLookupError:
        mx = []
    if mx and mx != [(0, "")] and mx != [(0, ".")]:
        out.append(Finding("parked", "info", "parked.mx", "This parked domain still has MX records.",
                           f'If it should not receive mail either, publish a null MX: "{domain}. MX 0 ."'))
    return out


def selectors_for(session: Session, domain: str, days: int = 30, now: datetime | None = None) -> list[tuple[str, str]]:
    """(signing domain, selector) pairs seen for ``domain`` and its subdomains in recent reports."""
    since = (now or datetime.now(UTC)) - timedelta(days=days)
    rows = session.execute(
        select(m.AuthResult.selector, m.AuthResult.domain)
        .join(m.AggregateRecord, m.AuthResult.record_id == m.AggregateRecord.id)
        .join(m.AggregateReport, m.AggregateRecord.report_id == m.AggregateReport.id)
        .where(
            m.AuthResult.method == "dkim",
            m.AuthResult.selector.is_not(None),
            or_(m.AuthResult.domain == domain, m.AuthResult.domain.like(f"%.{domain}")),
            m.AggregateReport.date_end >= since,
        )
        .distinct()
    ).all()
    return sorted({(d, sel) for sel, d in rows if sel and d and "%" not in sel})


def run_dns_checks(session: Session, settings: Settings | None = None, resolver: Resolver | None = None,
                   now: datetime | None = None) -> dict[str, Any]:
    s = settings or get_settings()
    resolver = resolver or DnsPythonResolver(s.dns_nameservers or None, s.dns_timeout_seconds)
    now = now or datetime.now(UTC)
    domains = session.scalars(select(m.Domain).where(m.Domain.active.is_(True)).order_by(m.Domain.name)).all()
    summary = {}
    for d in domains:
        result = check_domain(d.name, resolver, selectors_for(session, d.name, now=now), d.parked)
        counts = {sev: sum(1 for f in result["findings"] if f["severity"] == sev) for sev in ("error", "warning")}
        session.add(m.DnsCheck(domain=d.name, checked_at=now, result=result, findings=result["findings"],
                               error_count=counts["error"], warning_count=counts["warning"]))
        summary[d.name] = counts
    session.flush()
    return summary


def latest_check(session: Session, domain: str) -> m.DnsCheck | None:
    return session.scalars(
        select(m.DnsCheck).where(m.DnsCheck.domain == domain).order_by(m.DnsCheck.checked_at.desc()).limit(1)
    ).first()

