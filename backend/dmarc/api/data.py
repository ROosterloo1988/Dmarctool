"""Read-only data endpoints for dashboards, sources, records, reports, IPs, DNS and RUF."""

from __future__ import annotations

import csv
import gzip
import io
from datetime import UTC, date, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from dmarc.analysis import readiness, recommendations, source_overview
from dmarc.config import Settings
from dmarc.db import models as m
from dmarc.dnscheck.run import latest_check
from dmarc.dnscheck.spf import evaluate_stored
from dmarc.senders import load_catalog

from .deps import CurrentUser, audit, csrf_protect, current_user, get_db, get_settings_dep, require_admin

router = APIRouter(prefix="/api", dependencies=[Depends(current_user), Depends(csrf_protect)])

MAX_PAGE = 500
MAX_EXPORT = 200_000


def _domain_or_404(db: Session, domain: str) -> m.Domain:
    d = db.scalars(select(m.Domain).where(m.Domain.name == domain.lower())).one_or_none()
    if d is None:
        raise HTTPException(404, f"domain {domain} is not monitored")
    return d


def _now() -> datetime:
    return datetime.now(UTC)


def _pct(a: int, b: int) -> float | None:
    return round(100.0 * a / b, 1) if b else None


# --------------------------------------------------------------------------------------
# Domains overview & dashboard
# --------------------------------------------------------------------------------------

@router.get("/domains")
def list_domains(db: Session = Depends(get_db), settings: Settings = Depends(get_settings_dep)):
    since = (_now() - timedelta(days=settings.analysis_days)).date()
    totals = {row.domain: row for row in db.execute(
        select(m.DailyStat.domain, func.sum(m.DailyStat.messages).label("messages"),
               func.sum(m.DailyStat.dmarc_pass).label("dmarc_pass"))
        .where(m.DailyStat.day >= since).group_by(m.DailyStat.domain))}
    out = []
    for d in db.scalars(select(m.Domain).order_by(m.Domain.name)):
        t = totals.get(d.name)
        check = latest_check(db, d.name)
        dmarc = (check.result.get("dmarc") if check else {}) or {}
        out.append({
            "name": d.name, "active": d.active, "parked": d.parked,
            "messages": int(t.messages) if t else 0,
            "dmarc_pass_pct": _pct(int(t.dmarc_pass), int(t.messages)) if t else None,
            "policy": dmarc.get("effective_policy"),
            "dns_errors": check.error_count if check else None,
            "dns_warnings": check.warning_count if check else None,
            "dns_checked_at": check.checked_at if check else None,
        })
    return out


@router.get("/domains/{domain}/dashboard")
def dashboard(domain: str, days: int = Query(30, ge=1, le=730), db: Session = Depends(get_db),
              settings: Settings = Depends(get_settings_dep)):
    _domain_or_404(db, domain)
    now = _now()
    start = (now - timedelta(days=days - 1)).date()
    prev_start = start - timedelta(days=days)
    ds = m.DailyStat

    def totals(a: date, b: date) -> dict[str, int]:
        row = db.execute(select(
            func.coalesce(func.sum(ds.messages), 0), func.coalesce(func.sum(ds.dmarc_pass), 0),
            func.coalesce(func.sum(ds.spf_aligned), 0), func.coalesce(func.sum(ds.dkim_aligned), 0),
            func.coalesce(func.sum(ds.disp_quarantine), 0), func.coalesce(func.sum(ds.disp_reject), 0),
            func.coalesce(func.sum(ds.forwarded), 0),
        ).where(ds.domain == domain, ds.day >= a, ds.day < b)).one()
        keys = ("messages", "dmarc_pass", "spf_aligned", "dkim_aligned", "quarantined", "rejected", "forwarded")
        return dict(zip(keys, map(int, row), strict=True))

    cur = totals(start, now.date() + timedelta(days=1))
    prev = totals(prev_start, start)
    series = {r.day: r for r in db.execute(
        select(ds.day, func.sum(ds.messages).label("messages"), func.sum(ds.dmarc_pass).label("dmarc_pass"),
               func.sum(ds.spf_aligned).label("spf_aligned"), func.sum(ds.dkim_aligned).label("dkim_aligned"))
        .where(ds.domain == domain, ds.day >= start).group_by(ds.day))}
    trend = []
    for i in range(days):
        day = start + timedelta(days=i)
        r = series.get(day)
        msgs = int(r.messages) if r else 0
        passed = int(r.dmarc_pass) if r else 0
        trend.append({"day": day.isoformat(), "messages": msgs, "pass": passed, "fail": msgs - passed,
                      "pass_pct": _pct(passed, msgs)})
    top = db.execute(
        select(ds.source_key, func.max(ds.source_name).label("name"), func.sum(ds.messages).label("messages"),
               func.sum(ds.dmarc_pass).label("dmarc_pass"))
        .where(ds.domain == domain, ds.day >= start).group_by(ds.source_key)
        .order_by(func.sum(ds.messages).desc()).limit(8)).all()

    catalog = load_catalog()
    sources = source_overview(db, domain, settings.analysis_days, now, catalog, settings)
    recs = recommendations(db, domain, now, settings, catalog, sources)
    check = latest_check(db, domain)
    return {
        "domain": domain, "days": days,
        "totals": cur | {"dmarc_pass_pct": _pct(cur["dmarc_pass"], cur["messages"]),
                         "spf_aligned_pct": _pct(cur["spf_aligned"], cur["messages"]),
                         "dkim_aligned_pct": _pct(cur["dkim_aligned"], cur["messages"])},
        "previous": prev | {"dmarc_pass_pct": _pct(prev["dmarc_pass"], prev["messages"])},
        "trend": trend,
        "top_sources": [{"key": t.source_key, "name": t.name, "messages": int(t.messages),
                         "dmarc_pass_pct": _pct(int(t.dmarc_pass), int(t.messages))} for t in top],
        "readiness": readiness(db, domain, now, settings, catalog, sources, check),
        "recommendations": [r.as_dict() for r in recs[:6]],
        "recommendation_count": len(recs),
        "dns": {"checked_at": check.checked_at, "errors": check.error_count, "warnings": check.warning_count} if check else None,
    }


@router.get("/domains/{domain}/recommendations")
def domain_recommendations(domain: str, db: Session = Depends(get_db), settings: Settings = Depends(get_settings_dep)):
    _domain_or_404(db, domain)
    return [r.as_dict() for r in recommendations(db, domain, _now(), settings)]


@router.get("/domains/{domain}/readiness")
def domain_readiness(domain: str, db: Session = Depends(get_db), settings: Settings = Depends(get_settings_dep)):
    _domain_or_404(db, domain)
    return readiness(db, domain, _now(), settings)


# --------------------------------------------------------------------------------------
# Sources
# --------------------------------------------------------------------------------------

def _sources(db: Session, domain: str, days: int, settings: Settings) -> list[dict[str, Any]]:
    sources = source_overview(db, domain, days, _now(), load_catalog(), settings)
    notes = {c.source_key: c for c in db.scalars(select(m.SourceClassification).where(m.SourceClassification.domain == domain))}
    asn_info = {}
    ips = {ip for s in sources for ip in s.ips}
    if ips:
        for info in db.scalars(select(m.IpInfo).where(m.IpInfo.ip.in_(list(ips)))):
            asn_info[str(info.ip)] = info
    out = []
    for s in sources:
        d = s.as_dict()
        c = notes.get(s.key)
        d["note"] = c.note if c else None
        d["classified_by"] = c.updated_by if c else None
        infos = [asn_info[ip] for ip in s.ips if ip in asn_info]
        d["asns"] = sorted({f"AS{i.asn} {i.as_org or ''}".strip() for i in infos if i.asn})[:5]
        d["countries"] = sorted({i.country for i in infos if i.country})
        d["ips"] = sorted(s.ips)[:50]
        out.append(d)
    return out


@router.get("/domains/{domain}/sources")
def list_sources(domain: str, days: int = Query(30, ge=1, le=730), db: Session = Depends(get_db),
                 settings: Settings = Depends(get_settings_dep)):
    _domain_or_404(db, domain)
    return _sources(db, domain, days, settings)


@router.get("/domains/{domain}/sources.csv")
def export_sources(domain: str, request: Request, days: int = Query(30, ge=1, le=730), db: Session = Depends(get_db),
                   settings: Settings = Depends(get_settings_dep), user: CurrentUser = Depends(current_user)):
    _domain_or_404(db, domain)
    rows = _sources(db, domain, days, settings)
    cols = ["name", "key", "category", "status", "messages", "failing", "dmarc_pass_pct", "spf_aligned_pct",
            "dkim_aligned_pct", "spf_pass_pct", "dkim_pass_pct", "ip_count", "asns", "countries", "note"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([_csv_cell("; ".join(r[c]) if isinstance(r.get(c), list) else r.get(c)) for c in cols])
    audit(db, request, user.label, "export", f"sources:{domain}", days=days)
    return Response(buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="sources-{domain}-{days}d.csv"'})


# --------------------------------------------------------------------------------------
# Records (explore + CSV)
# --------------------------------------------------------------------------------------

def _record_query(db: Session, domain: str | None, date_from: date | None, date_to: date | None,
                  reporter: str | None, result: str | None, source_key: str | None, ip: str | None,
                  header_from: str | None, disposition: str | None, report_id: int | None):
    r, rep, info = m.AggregateRecord, m.AggregateReport, m.IpInfo
    q = (select(r, rep, info).join(rep, rep.id == r.report_id)
         .outerjoin(info, info.ip == r.source_ip))
    conds = []
    if domain:
        conds.append(rep.domain == domain.lower())
    if date_from:
        conds.append(rep.date_end >= datetime.combine(date_from, datetime.min.time(), UTC))
    if date_to:
        conds.append(rep.date_begin < datetime.combine(date_to + timedelta(days=1), datetime.min.time(), UTC))
    if reporter:
        conds.append(rep.org_name == reporter)
    if source_key:
        conds.append(func.coalesce(r.source_key, "pending") == source_key)
    if ip:
        conds.append(r.source_ip == ip)
    if header_from:
        conds.append(r.header_from == header_from.lower())
    if disposition:
        conds.append(r.disposition == disposition)
    if report_id:
        conds.append(r.report_id == report_id)
    if result == "pass":
        conds.append(r.dmarc_pass.is_(True))
    elif result == "fail":
        conds.append(r.dmarc_pass.is_(False))
    elif result == "spf_unaligned":
        conds.append(r.spf_aligned.is_(False))
    elif result == "dkim_unaligned":
        conds.append(r.dkim_aligned.is_(False))
    if conds:
        q = q.where(and_(*conds))
    return q


def _record_filters(
    domain: str | None = None, date_from: date | None = Query(None, alias="from"), date_to: date | None = Query(None, alias="to"),
    reporter: str | None = None, result: str | None = Query(None, pattern="^(pass|fail|spf_unaligned|dkim_unaligned)$"),
    source: str | None = None, ip: str | None = None, header_from: str | None = None,
    disposition: str | None = Query(None, pattern="^(none|quarantine|reject)$"), report: int | None = None,
) -> dict[str, Any]:
    if ip:
        import ipaddress

        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            raise HTTPException(422, "invalid ip") from None
    return dict(domain=domain, date_from=date_from, date_to=date_to, reporter=reporter, result=result,
                source_key=source, ip=ip, header_from=header_from, disposition=disposition, report_id=report)


def _auth_results(db: Session, record_ids: list[int]) -> dict[int, list[dict]]:
    out: dict[int, list[dict]] = {}
    if not record_ids:
        return out
    for a in db.scalars(select(m.AuthResult).where(m.AuthResult.record_id.in_(record_ids)).order_by(m.AuthResult.id)):
        out.setdefault(a.record_id, []).append({"method": a.method, "domain": a.domain, "selector": a.selector,
                                                "scope": a.scope, "result": a.result, "aligned": a.aligned})
    return out


def _record_dict(r: m.AggregateRecord, rep: m.AggregateReport, info: m.IpInfo | None, auth: list[dict],
                 names: dict[str, str]) -> dict[str, Any]:
    key = r.source_key or "pending"
    return {
        "id": r.id, "report": {"id": rep.id, "org_name": rep.org_name, "report_id": rep.report_id,
                               "date_begin": rep.date_begin, "date_end": rep.date_end},
        "domain": rep.domain, "source_ip": str(r.source_ip), "ptr": info.ptr if info else None,
        "ptr_confirmed": bool(info and info.ptr_confirmed),
        "as_org": info.as_org if info else None, "asn": info.asn if info else None,
        "country": info.country if info else None, "source_key": key, "source_name": names.get(key, key),
        "count": r.count, "disposition": r.disposition, "header_from": r.header_from,
        "envelope_from": r.envelope_from, "envelope_to": r.envelope_to, "spf_aligned": r.spf_aligned,
        "dkim_aligned": r.dkim_aligned, "dmarc_pass": r.dmarc_pass, "reasons": r.reasons, "auth": auth,
    }


def _names_for(db: Session, keys: set[str]) -> dict[str, str]:
    from dmarc.enrich import source_names

    return source_names(db, keys, load_catalog()) if keys else {}


@router.get("/records")
def list_records(filters: dict = Depends(_record_filters), page: int = Query(1, ge=1),
                 page_size: int = Query(50, ge=1, le=MAX_PAGE), db: Session = Depends(get_db)):
    q = _record_query(db, **filters)
    sub = q.with_only_columns(m.AggregateRecord.count).subquery()
    total, messages = db.execute(select(func.count(), func.coalesce(func.sum(sub.c.count), 0)).select_from(sub)).one()
    rows = db.execute(q.order_by(m.AggregateReport.date_begin.desc(), m.AggregateRecord.count.desc())
                      .offset((page - 1) * page_size).limit(page_size)).all()
    auth = _auth_results(db, [r.id for r, _, _ in rows])
    names = _names_for(db, {r.source_key or "pending" for r, _, _ in rows})
    return {"total": total, "messages": int(messages), "page": page, "page_size": page_size,
            "items": [_record_dict(r, rep, info, auth.get(r.id, []), names) for r, rep, info in rows]}


CSV_COLUMNS = ["report_begin", "report_end", "reporter", "report_id", "domain", "source_ip", "ptr", "asn", "as_org",
               "country", "source", "count", "disposition", "header_from", "envelope_from", "dmarc_pass",
               "spf_aligned", "dkim_aligned", "spf_results", "dkim_results"]


def _csv_cell(v: Any) -> Any:
    # Prevent formula injection when opened in Excel.
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


@router.get("/records.csv")
def export_records(request: Request, filters: dict = Depends(_record_filters), db: Session = Depends(get_db),
                   user: CurrentUser = Depends(current_user)):
    audit(db, request, user.label, "export", "records", **{k: str(v) for k, v in filters.items() if v})
    db.commit()
    sessions = request.app.state.sessions

    def generate():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(CSV_COLUMNS)
        yield buf.getvalue()
        # Own session: the request-scoped one may be closed while the response streams.
        with sessions() as s:
            q = _record_query(s, **filters).order_by(m.AggregateReport.date_begin, m.AggregateRecord.id)
            offset, size = 0, 2000
            while offset < MAX_EXPORT:
                rows = s.execute(q.offset(offset).limit(size)).all()
                if not rows:
                    break
                auth = _auth_results(s, [r.id for r, _, _ in rows])
                names = _names_for(s, {r.source_key or "pending" for r, _, _ in rows})
                buf.seek(0)
                buf.truncate()
                for r, rep, info in rows:
                    a = auth.get(r.id, [])
                    spf = "; ".join(f"{x['domain']}={x['result']}" for x in a if x["method"] == "spf")
                    dk = "; ".join(f"{x['domain']}/{x['selector']}={x['result']}" for x in a if x["method"] == "dkim")
                    key = r.source_key or "pending"
                    w.writerow([_csv_cell(v) for v in (
                        rep.date_begin.isoformat(), rep.date_end.isoformat(), rep.org_name, rep.report_id, rep.domain,
                        str(r.source_ip), info.ptr if info else "", info.asn if info else "",
                        info.as_org if info else "", info.country if info else "", names.get(key, key), r.count,
                        r.disposition, r.header_from, r.envelope_from, r.dmarc_pass, r.spf_aligned, r.dkim_aligned,
                        spf, dk)])
                yield buf.getvalue()
                offset += size
                if len(rows) < size:
                    break

    return StreamingResponse(generate(), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": 'attachment; filename="dmarc-records.csv"'})


@router.get("/reporters")
def reporters(domain: str | None = None, db: Session = Depends(get_db)):
    q = select(m.AggregateReport.org_name, func.count()).group_by(m.AggregateReport.org_name).order_by(func.count().desc())
    if domain:
        q = q.where(m.AggregateReport.domain == domain.lower())
    return [{"org_name": o, "reports": n} for o, n in db.execute(q)]


# --------------------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------------------

@router.get("/reports")
def list_reports(domain: str | None = None, reporter: str | None = None, date_from: date | None = Query(None, alias="from"),
                 date_to: date | None = Query(None, alias="to"), page: int = Query(1, ge=1),
                 page_size: int = Query(50, ge=1, le=MAX_PAGE), db: Session = Depends(get_db)):
    rep = m.AggregateReport
    passing = (select(func.coalesce(func.sum(m.AggregateRecord.count), 0))
               .where(m.AggregateRecord.report_id == rep.id, m.AggregateRecord.dmarc_pass.is_(True))
               .correlate(rep).scalar_subquery())
    nrec = select(func.count()).where(m.AggregateRecord.report_id == rep.id).correlate(rep).scalar_subquery()
    q = select(rep.id, rep.org_name, rep.report_id, rep.domain, rep.date_begin, rep.date_end, rep.message_count,
               rep.p, rep.errors, passing.label("passing"), nrec.label("records"))
    if domain:
        q = q.where(rep.domain == domain.lower())
    if reporter:
        q = q.where(rep.org_name == reporter)
    if date_from:
        q = q.where(rep.date_end >= datetime.combine(date_from, datetime.min.time(), UTC))
    if date_to:
        q = q.where(rep.date_begin < datetime.combine(date_to + timedelta(days=1), datetime.min.time(), UTC))
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = db.execute(q.order_by(rep.date_begin.desc(), rep.id.desc()).offset((page - 1) * page_size).limit(page_size))
    return {"total": total, "page": page, "page_size": page_size, "items": [
        {"id": r.id, "org_name": r.org_name, "report_id": r.report_id, "domain": r.domain, "date_begin": r.date_begin,
         "date_end": r.date_end, "messages": r.message_count, "dmarc_pass_pct": _pct(int(r.passing), r.message_count),
         "policy": r.p, "records": r.records, "errors": r.errors} for r in rows]}


@router.get("/reports/{report_id}")
def get_report(report_id: int, db: Session = Depends(get_db)):
    rep = db.get(m.AggregateReport, report_id)
    if rep is None:
        raise HTTPException(404, "report not found")
    inbound = db.get(m.InboundMessage, rep.inbound_message_id) if rep.inbound_message_id else None
    return {
        "id": rep.id, "org_name": rep.org_name, "report_id": rep.report_id, "domain": rep.domain, "email": rep.email,
        "extra_contact_info": rep.extra_contact_info, "date_begin": rep.date_begin, "date_end": rep.date_end,
        "version": rep.version, "generator": rep.generator, "errors": rep.errors, "messages": rep.message_count,
        "policy": {"p": rep.p, "sp": rep.sp, "np": rep.np, "pct": rep.pct, "adkim": rep.adkim, "aspf": rep.aspf,
                   "fo": rep.fo, "testing": rep.testing},
        "has_xml": rep.raw_xml_gz is not None, "created_at": rep.created_at,
        "inbound": {"id": inbound.id, "subject": inbound.subject, "received_at": inbound.received_at,
                    "moved_to": inbound.moved_to} if inbound else None,
    }


@router.get("/reports/{report_id}/xml")
def report_xml(report_id: int, db: Session = Depends(get_db)):
    rep = db.get(m.AggregateReport, report_id)
    if rep is None or rep.raw_xml_gz is None:
        raise HTTPException(404, "no XML stored for this report")
    # Served as a download with nosniff so it is never rendered/executed by the browser.
    return Response(gzip.decompress(rep.raw_xml_gz), media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="report-{rep.id}.xml"'})


# --------------------------------------------------------------------------------------
# IP detail
# --------------------------------------------------------------------------------------

@router.get("/ips/{ip}")
def ip_detail(ip: str, db: Session = Depends(get_db)):
    import ipaddress

    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        raise HTTPException(422, "invalid ip") from None
    info = db.get(m.IpInfo, ip)
    r, rep = m.AggregateRecord, m.AggregateReport
    per_domain = db.execute(
        select(rep.domain, func.sum(r.count), func.sum(r.count).filter(r.dmarc_pass),
               func.min(rep.date_begin), func.max(rep.date_end))
        .join(rep, rep.id == r.report_id).where(r.source_ip == ip).group_by(rep.domain)).all()
    reporters_ = db.execute(
        select(rep.org_name, func.sum(r.count)).join(rep, rep.id == r.report_id).where(r.source_ip == ip)
        .group_by(rep.org_name).order_by(func.sum(r.count).desc())).all()
    spf = {}
    for d, *_ in per_domain:
        check = latest_check(db, d)
        if check:
            s = check.result.get("spf") or {}
            spf[d] = evaluate_stored(s.get("tree"), ip, s.get("lookups", 0))
    catalog = load_catalog()
    sender = catalog.get(info.sender_key) if info else None
    return {
        "ip": ip,
        "info": {"ptr": info.ptr, "ptr_confirmed": info.ptr_confirmed, "asn": info.asn, "as_org": info.as_org,
                 "country": info.country, "sender": sender.name if sender else None,
                 "updated_at": info.updated_at} if info else None,
        "domains": [{"domain": d, "messages": int(n or 0), "dmarc_pass_pct": _pct(int(p or 0), int(n or 0)),
                     "first_seen": a, "last_seen": b, "spf_result": spf.get(d)} for d, n, p, a, b in per_domain],
        "reporters": [{"org_name": o, "messages": int(n)} for o, n in reporters_],
    }


# --------------------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------------------

@router.get("/domains/{domain}/dns")
def dns_status(domain: str, db: Session = Depends(get_db)):
    _domain_or_404(db, domain)
    check = latest_check(db, domain)
    history = db.execute(
        select(m.DnsCheck.checked_at, m.DnsCheck.error_count, m.DnsCheck.warning_count)
        .where(m.DnsCheck.domain == domain).order_by(m.DnsCheck.checked_at.desc()).limit(30)).all()
    return {"latest": {"checked_at": check.checked_at, "result": check.result, "findings": check.findings,
                       "errors": check.error_count, "warnings": check.warning_count} if check else None,
            "history": [{"checked_at": h.checked_at, "errors": h.error_count, "warnings": h.warning_count} for h in history]}


# --------------------------------------------------------------------------------------
# Forensic (RUF) - admins only: contains personal data
# --------------------------------------------------------------------------------------

@router.get("/forensic", dependencies=[Depends(require_admin)])
def list_forensic(domain: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=MAX_PAGE),
                  db: Session = Depends(get_db)):
    f = m.ForensicReport
    q = select(f)
    if domain:
        q = q.where(f.reported_domain == domain.lower())
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = db.scalars(q.order_by(f.arrival_date.desc().nulls_last(), f.id.desc()).offset((page - 1) * page_size).limit(page_size))
    return {"total": total, "items": [
        {"id": x.id, "arrival_date": x.arrival_date, "reporter": x.reporter, "source_ip": str(x.source_ip) if x.source_ip else None,
         "reported_domain": x.reported_domain, "auth_failure": x.auth_failure, "delivery_result": x.delivery_result,
         "original_from": x.original_from, "original_subject": x.original_subject, "expires_at": x.expires_at}
        for x in rows]}


@router.get("/forensic/{fid}", dependencies=[Depends(require_admin)])
def get_forensic(fid: int, request: Request, db: Session = Depends(get_db), user: CurrentUser = Depends(require_admin)):
    x = db.get(m.ForensicReport, fid)
    if x is None:
        raise HTTPException(404, "not found")
    audit(db, request, user.label, "view_forensic", str(fid))
    return {
        "id": x.id, "feedback_type": x.feedback_type, "reporter": x.reporter, "user_agent": x.user_agent,
        "arrival_date": x.arrival_date, "source_ip": str(x.source_ip) if x.source_ip else None,
        "reported_domain": x.reported_domain, "original_mail_from": x.original_mail_from,
        "original_rcpt_to": x.original_rcpt_to, "auth_failure": x.auth_failure, "delivery_result": x.delivery_result,
        "authentication_results": x.authentication_results, "dkim_domain": x.dkim_domain, "dkim_selector": x.dkim_selector,
        "spf_dns": x.spf_dns, "identity_alignment": x.identity_alignment, "original_subject": x.original_subject,
        "original_from": x.original_from, "original_to": x.original_to, "original_message_id": x.original_message_id,
        "original_date": x.original_date, "original_headers": x.original_headers,
        "body_stored": x.original_body is not None,
        "original_body": x.original_body.decode("utf-8", errors="replace") if x.original_body is not None else None,
        "expires_at": x.expires_at,
    }
