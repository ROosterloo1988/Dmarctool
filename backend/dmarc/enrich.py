"""Enrichment of source IPs (reverse DNS, ASN, country) and assignment of sources to records."""

from __future__ import annotations

import ipaddress
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import bindparam, func, or_, select, text, union, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from dmarc.config import Settings, get_settings
from dmarc.db import models as m
from dmarc.dnscheck.resolver import DnsLookupError, Resolver, TempError
from dmarc.geoip import GeoIp
from dmarc.senders import Catalog

log = logging.getLogger(__name__)


def reverse_dns(ip: str, resolver: Resolver) -> tuple[str | None, bool]:
    """PTR name and whether it is forward-confirmed (PTR name resolves back to the IP)."""
    try:
        names = resolver.ptr(ip)
    except TempError:
        raise
    except DnsLookupError:
        return None, False
    if not names:
        return None, False
    name = names[0].rstrip(".").lower()
    lookup = resolver.aaaa if ipaddress.ip_address(ip).version == 6 else resolver.a
    try:
        confirmed = any(ipaddress.ip_address(a) == ipaddress.ip_address(ip) for a in lookup(name))
    except DnsLookupError:
        confirmed = False
    return name[:253], confirmed


def enrich_ips(session: Session, resolver: Resolver, geo: GeoIp, catalog: Catalog,
               settings: Settings | None = None, now: datetime | None = None, limit: int = 500) -> int:
    s = settings or get_settings()
    now = now or datetime.now(UTC)
    stale = now - timedelta(days=s.ip_info_max_age_days)
    # Source IPs from aggregate records and from failure reports.
    seen = union(select(m.AggregateRecord.source_ip.label("ip")),
                 select(m.ForensicReport.source_ip.label("ip")).where(m.ForensicReport.source_ip.is_not(None))).subquery()
    ips = session.scalars(
        select(seen.c.ip)
        .outerjoin(m.IpInfo, m.IpInfo.ip == seen.c.ip)
        .where(or_(m.IpInfo.ip.is_(None), m.IpInfo.updated_at < stale))
        .limit(limit)
    ).all()
    done = 0
    for ip in map(str, ips):
        try:
            ptr, confirmed = reverse_dns(ip, resolver)
        except TempError as exc:
            log.info("PTR lookup for %s failed temporarily: %s", ip, exc)
            continue
        g = geo.lookup(ip)
        sender = catalog.by_ptr(ptr) if confirmed else None
        sender = sender or catalog.by_asn(g.asn)
        values = dict(ip=ip, ptr=ptr, ptr_confirmed=confirmed, asn=g.asn, as_org=(g.as_org or None) and g.as_org[:255],
                      country=g.country, sender_key=sender.key if sender else None, updated_at=now)
        stmt = pg_insert(m.IpInfo).values(**values)
        session.execute(stmt.on_conflict_do_update(index_elements=["ip"], set_={k: stmt.excluded[k] for k in values if k != "ip"}))
        done += 1
    session.flush()
    return done


def source_key_for(catalog: Catalog, ip: str, ptr: str | None, confirmed: bool, asn: int | None,
                   dkim_pass_domains: list[str], spf_pass_domains: list[str]) -> str:
    sender = catalog.identify(ptr if confirmed else None, asn, dkim_pass_domains, spf_pass_domains)
    if sender:
        return f"sender:{sender.key}"
    if asn:
        return f"asn:{asn}"
    return f"ip:{ip}"


def assign_sources(session: Session, catalog: Catalog, reassign: bool = False, batch: int = 2000) -> int:
    """Set aggregate_record.source_key for records whose IP has been enriched."""
    if reassign:
        session.execute(update(m.AggregateRecord).values(source_key=None))
    total = 0
    sql = text("""
        SELECT r.id, host(r.source_ip) AS ip, r.envelope_from, i.ptr, i.ptr_confirmed, i.asn,
               coalesce(array_agg(a.domain) FILTER (WHERE a.method = 'dkim' AND a.result = 'pass'), '{}') AS dkim,
               coalesce(array_agg(coalesce(a.domain, r.envelope_from))
                        FILTER (WHERE a.method = 'spf' AND a.result = 'pass'), '{}') AS spf
        FROM aggregate_record r
        JOIN ip_info i ON i.ip = r.source_ip
        LEFT JOIN auth_result a ON a.record_id = r.id
        WHERE r.source_key IS NULL
        GROUP BY r.id, r.source_ip, r.envelope_from, i.ptr, i.ptr_confirmed, i.asn
        ORDER BY r.id
        LIMIT :batch
    """)
    tbl = m.AggregateRecord.__table__
    upd = update(tbl).where(tbl.c.id == bindparam("rid")).values(source_key=bindparam("key"))
    while True:
        rows = session.execute(sql, {"batch": batch}).all()
        if not rows:
            break
        params = [{"rid": r.id, "key": source_key_for(catalog, r.ip, r.ptr, r.ptr_confirmed, r.asn,
                                                       [d for d in r.dkim if d], [d for d in r.spf if d])}
                  for r in rows]
        session.connection().execute(upd, params)
        total += len(params)
    session.flush()
    return total


def source_names(session: Session, keys: set[str], catalog: Catalog) -> dict[str, str]:
    """Human-readable name for each source key."""
    names: dict[str, str] = {}
    asns = {int(k[4:]) for k in keys if k.startswith("asn:") and k[4:].isdigit()}
    orgs = dict(session.execute(
        select(m.IpInfo.asn, func.max(m.IpInfo.as_org)).where(m.IpInfo.asn.in_(asns)).group_by(m.IpInfo.asn)
    ).all()) if asns else {}
    ips = [k[3:] for k in keys if k.startswith("ip:")]
    ptrs = {str(ip): ptr for ip, ptr in session.execute(
        select(m.IpInfo.ip, m.IpInfo.ptr).where(m.IpInfo.ip.in_(ips)))} if ips else {}
    for k in keys:
        if k.startswith("sender:"):
            s = catalog.get(k[7:])
            names[k] = s.name if s else k[7:]
        elif k.startswith("asn:"):
            org = orgs.get(int(k[4:])) if k[4:].isdigit() else None
            names[k] = f"{org} (AS{k[4:]})" if org else f"AS{k[4:]}"
        elif k.startswith("ip:"):
            names[k] = ptrs.get(k[3:]) or k[3:]
        else:
            names[k] = "Not yet identified" if k == "pending" else k
    return names
