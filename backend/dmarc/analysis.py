"""Source overview, plain-language recommendations and the "ready for p=reject" indicator."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from dmarc.config import Settings, get_settings
from dmarc.db import models as m
from dmarc.dnscheck.run import latest_check
from dmarc.enrich import source_names
from dmarc.parsing.alignment import organizational_domain
from dmarc.senders import Catalog, Sender, load_catalog

SOURCES_SQL = text("""
    WITH rec AS (
        SELECT r.id, r.count, r.source_ip, coalesce(r.source_key, 'pending') AS source_key,
               r.dmarc_pass, r.spf_aligned, r.dkim_aligned, r.envelope_from, r.reasons,
               rep.date_begin
        FROM aggregate_record r JOIN aggregate_report rep ON rep.id = r.report_id
        WHERE rep.domain = :domain AND rep.date_end >= :since
    ), auth AS (
        SELECT a.record_id,
               bool_or(a.method = 'spf'  AND a.result = 'pass') AS spf_pass,
               bool_or(a.method = 'dkim' AND a.result = 'pass') AS dkim_pass,
               array_agg(DISTINCT a.domain) FILTER (WHERE a.method = 'dkim' AND a.result = 'pass') AS dkim_domains,
               array_agg(DISTINCT a.domain || '/' || coalesce(a.selector, '')) FILTER (WHERE a.method = 'dkim') AS selectors,
               array_agg(DISTINCT coalesce(a.domain, '')) FILTER (WHERE a.method = 'spf' AND coalesce(a.scope, 'mfrom') = 'mfrom') AS spf_domains
        FROM auth_result a WHERE a.record_id IN (SELECT id FROM rec) GROUP BY a.record_id
    )
    SELECT rec.*, coalesce(auth.spf_pass, false) AS spf_pass, coalesce(auth.dkim_pass, false) AS dkim_pass,
           auth.dkim_domains, auth.selectors, auth.spf_domains,
           EXISTS (SELECT 1 FROM jsonb_array_elements(rec.reasons) x
                   WHERE x->>'type' IN ('forwarded', 'mailing_list', 'trusted_forwarder')) AS forwarded
    FROM rec LEFT JOIN auth ON auth.record_id = rec.id
""")


@dataclass
class Source:
    key: str
    name: str
    sender: Sender | None
    status: str | None  # legit | unknown | abuse | None (unclassified)
    messages: int = 0
    dmarc_pass: int = 0
    spf_aligned: int = 0
    dkim_aligned: int = 0
    spf_pass: int = 0
    dkim_pass: int = 0
    spf_pass_unaligned: int = 0
    dkim_pass_unaligned: int = 0
    forwarded_fail: int = 0
    ips: set[str] = field(default_factory=set)
    envelope_domains: Counter = field(default_factory=Counter)
    dkim_domains: Counter = field(default_factory=Counter)
    selectors: Counter = field(default_factory=Counter)
    spf_fail_ips: set[str] = field(default_factory=set)
    days: set = field(default_factory=set)

    @property
    def failing(self) -> int:
        return self.messages - self.dmarc_pass

    def pct(self, n: int) -> float:
        return round(100.0 * n / self.messages, 1) if self.messages else 0.0

    @property
    def recognised(self) -> bool:
        return self.sender is not None

    @property
    def considered_legit(self) -> bool:
        """Counts towards the "legitimate mail" pass rate used for p=reject readiness."""
        if self.status == "legit":
            return True
        if self.status in ("abuse", "unknown"):
            return False
        return self.recognised or self.pct(self.dmarc_pass) >= 50

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key, "name": self.name, "sender": self.sender.key if self.sender else None,
            "category": self.sender.category if self.sender else None, "status": self.status,
            "recognised": self.recognised, "considered_legit": self.considered_legit,
            "messages": self.messages, "failing": self.failing,
            "dmarc_pass_pct": self.pct(self.dmarc_pass), "spf_aligned_pct": self.pct(self.spf_aligned),
            "dkim_aligned_pct": self.pct(self.dkim_aligned), "spf_pass_pct": self.pct(self.spf_pass),
            "dkim_pass_pct": self.pct(self.dkim_pass), "ip_count": len(self.ips),
            "envelope_domains": dict(self.envelope_domains.most_common(5)),
            "dkim_domains": dict(self.dkim_domains.most_common(5)),
            "selectors": dict(self.selectors.most_common(5)),
        }


def source_overview(session: Session, domain: str, days: int | None = None, now: datetime | None = None,
                    catalog: Catalog | None = None, settings: Settings | None = None) -> list[Source]:
    s = settings or get_settings()
    catalog = catalog or load_catalog()
    now = now or datetime.now(UTC)
    since = now - timedelta(days=days or s.analysis_days)
    rows = session.execute(SOURCES_SQL, {"domain": domain, "since": since}).mappings().all()
    statuses = dict(session.execute(
        select(m.SourceClassification.source_key, m.SourceClassification.status)
        .where(m.SourceClassification.domain == domain)).all())
    names = source_names(session, {r["source_key"] for r in rows}, catalog)

    sources: dict[str, Source] = {}
    for r in rows:
        key = r["source_key"]
        src = sources.get(key)
        if src is None:
            sender = catalog.get(key[7:]) if key.startswith("sender:") else None
            src = sources[key] = Source(key, names.get(key, key), sender, statuses.get(key))
        n = r["count"]
        src.messages += n
        src.dmarc_pass += n * r["dmarc_pass"]
        src.spf_aligned += n * r["spf_aligned"]
        src.dkim_aligned += n * r["dkim_aligned"]
        src.spf_pass += n * r["spf_pass"]
        src.dkim_pass += n * r["dkim_pass"]
        src.spf_pass_unaligned += n * (r["spf_pass"] and not r["spf_aligned"])
        src.dkim_pass_unaligned += n * (r["dkim_pass"] and not r["dkim_aligned"])
        src.forwarded_fail += n * (r["forwarded"] and not r["dmarc_pass"])
        src.ips.add(str(r["source_ip"]))
        src.days.add(r["date_begin"].date())
        for d in r["spf_domains"] or [r["envelope_from"]]:
            if d:
                src.envelope_domains[d] += n
        for d in r["dkim_domains"] or []:
            if d:
                src.dkim_domains[d] += n
        for sel in r["selectors"] or []:
            src.selectors[sel] += n
        if not r["spf_pass"]:
            src.spf_fail_ips.add(str(r["source_ip"]))
    return sorted(sources.values(), key=lambda x: -x.messages)


# --------------------------------------------------------------------------------------
# Recommendations
# --------------------------------------------------------------------------------------

@dataclass
class Recommendation:
    severity: str  # error | warning | info
    code: str
    title: str
    text: str
    actions: list[str] = field(default_factory=list)
    source_key: str | None = None
    messages: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _report_days(session: Session, domain: str, now: datetime, window: int) -> int:
    """Number of distinct days covered by reports in the analysis window."""
    return session.scalar(
        select(func.count(func.distinct(func.date(m.AggregateReport.date_begin))))
        .where(m.AggregateReport.domain == domain, m.AggregateReport.date_end >= now - timedelta(days=window))) or 0


def _per_week(n: int, days: int) -> int:
    return round(n * 7 / max(days, 1))


def _fmt(n: int) -> str:
    return f"{n:,}".replace(",", ".") if n >= 10000 else f"{n:,}"


def recommendations(session: Session, domain: str, now: datetime | None = None, settings: Settings | None = None,
                    catalog: Catalog | None = None, sources: list[Source] | None = None) -> list[Recommendation]:
    s = settings or get_settings()
    catalog = catalog or load_catalog()
    now = now or datetime.now(UTC)
    sources = sources if sources is not None else source_overview(session, domain, s.analysis_days, now, catalog, s)
    days = _report_days(session, domain, now, s.analysis_days)  # extrapolate volumes from the days we have
    check = latest_check(session, domain)
    spf = (check.result.get("spf") if check else None) or {}
    our_includes = {i.lower() for i in spf.get("includes", [])}
    lookups = spf.get("lookups", 0)
    org = organizational_domain(domain)
    recs: list[Recommendation] = []

    # 1. DNS problems first: they affect everything.
    if check:
        for f in check.findings:
            if f["severity"] in ("error", "warning"):
                recs.append(Recommendation(f["severity"], f["code"], f["message"], "",
                                           [f["fix"]] if f.get("fix") else []))

    # 2. Per sending source
    for src in sources:
        if src.status == "abuse" or src.key == "pending":
            continue
        fail = src.failing - src.forwarded_fail
        if fail < s.significant_messages or src.pct(fail) < 2:
            continue
        week = _per_week(src.messages, days)
        if src.sender or src.status == "legit":
            recs.append(_sender_recommendation(src, domain, org, week, fail, our_includes, lookups))
        elif src.status is None and not src.considered_legit:
            recs.append(Recommendation(
                "warning", "source.unknown_failing",
                f"Unknown source {src.name} sent {_fmt(src.failing)} messages as {domain} that failed DMARC",
                f"{len(src.ips)} IP address(es), {src.pct(src.dmarc_pass)}% passes DMARC. "
                "If this is a service you use, mark it as legitimate and set up SPF/DKIM for it. "
                "If not, this is spoofing: p=quarantine/p=reject will stop it.",
                ["Classify this source as legitimate, unknown or abuse."], src.key, src.failing))

    forwarded = sum(x.forwarded_fail for x in sources)
    if forwarded >= s.significant_messages:
        recs.append(Recommendation(
            "info", "source.forwarding",
            f"{_fmt(forwarded)} failing messages were forwarded or sent via mailing lists",
            "Forwarding breaks SPF; DKIM normally survives. Make sure all your mail is DKIM-signed with "
            "your own domain so forwarded mail keeps passing DMARC.", [], None, forwarded))

    # 3. Policy progression
    ready = readiness(session, domain, now, s, catalog, sources, check)
    if ready["next_step"]:
        recs.append(Recommendation("info", "policy.next_step", ready["next_step"]["title"],
                                   ready["next_step"]["text"], ready["next_step"]["actions"]))
    order = {"error": 0, "warning": 1, "info": 2}
    return sorted(recs, key=lambda r: (order.get(r.severity, 9), -(r.messages or 0)))


def _sender_recommendation(src: Source, domain: str, org: str, week: int, fail: int,
                           our_includes: set[str], lookups: int) -> Recommendation:
    sender = src.sender
    name = sender.name if sender else src.name
    title = (f"{name} sends ~{_fmt(week)} mails/week on behalf of {domain}; "
             f"{src.pct(src.failing)}% fails DMARC")
    problems, actions = [], []

    foreign_dkim = [d for d in src.dkim_domains if organizational_domain(d) != org]
    if src.dkim_aligned < src.messages * 0.98:
        if foreign_dkim:
            problems.append(f"DKIM is signed with {', '.join(foreign_dkim[:3])} instead of your own domain (not aligned).")
        elif src.dkim_pass < src.messages * 0.5:
            problems.append("Messages are not (validly) DKIM-signed.")
        actions.append(f"Set up DKIM with your own domain: {sender.dkim_setup}" if sender and sender.dkim_setup
                       else f"Set up DKIM signing with {domain} for this service.")

    foreign_env = [d for d in src.envelope_domains if d and organizational_domain(d) != org]
    if src.spf_aligned < src.messages * 0.98:
        if src.spf_pass_unaligned and foreign_env:
            problems.append(f"SPF passes for {', '.join(foreign_env[:3])} (the service's bounce domain), "
                            "which is not aligned with your From domain.")
            if sender and sender.spf_alignable and sender.return_path_setup:
                actions.append(f"Optionally align SPF too: {sender.return_path_setup}")
            elif sender and not sender.spf_alignable:
                actions.append(f"{name} cannot align SPF; DMARC has to pass via DKIM.")
        elif src.spf_pass < src.messages * 0.98 and not foreign_env:
            problems.append(f"SPF fails for {_fmt(src.messages - src.spf_pass)} messages sent with your own domain "
                            f"as envelope sender ({len(src.spf_fail_ips)} IP addresses not authorised).")
            if sender and sender.spf_include:
                if sender.spf_include.lower() in our_includes:
                    actions.append(f"include:{sender.spf_include} is already in your SPF record; check that these "
                                   "IPs belong to your account at the provider.")
                else:
                    extra = f" Your SPF record already uses {lookups} of 10 DNS lookups." if lookups >= 8 else ""
                    actions.append(f"Add include:{sender.spf_include} to the SPF record of {domain}.{extra}")
            else:
                ips = ", ".join(sorted(src.spf_fail_ips)[:5])
                actions.append(f"Authorise the sending IP addresses in SPF (e.g. ip4:/ip6: for {ips}) or set up DKIM.")
    if not problems:
        problems.append("Part of the mail from this service fails both SPF and DKIM alignment.")
    return Recommendation("warning", "source.misaligned", title, " ".join(problems), actions, src.key, fail)


# --------------------------------------------------------------------------------------
# Readiness for p=reject
# --------------------------------------------------------------------------------------

def readiness(session: Session, domain: str, now: datetime | None = None, settings: Settings | None = None,
              catalog: Catalog | None = None, sources: list[Source] | None = None,
              check: m.DnsCheck | None = None) -> dict[str, Any]:
    s = settings or get_settings()
    now = now or datetime.now(UTC)
    sources = sources if sources is not None else source_overview(session, domain, s.analysis_days, now, catalog, s)
    check = check or latest_check(session, domain)
    dmarc = (check.result.get("dmarc") if check else None) or {}
    findings = check.findings if check else []
    policy = dmarc.get("effective_policy")
    pct_tag = str((dmarc.get("tags") or {}).get("pct", "100"))
    pct = int(pct_tag) if pct_tag.isdigit() else 100

    legit = [x for x in sources if x.considered_legit]
    # Forwarded / mailing-list failures are excluded: they are expected and not fixable by us.
    legit_msgs = sum(x.messages - x.forwarded_fail for x in legit)
    legit_pass = sum(x.dmarc_pass for x in legit)
    pass_rate = round(100.0 * legit_pass / legit_msgs, 1) if legit_msgs else None
    failing_legit = [x for x in legit if (x.failing - x.forwarded_fail) >= s.significant_messages
                     and x.pct(x.failing - x.forwarded_fail) >= 2]
    unknown_failing = [x for x in sources if not x.considered_legit and x.status != "abuse"
                       and x.failing >= s.significant_messages]
    report_days = _report_days(session, domain, now, s.analysis_days)

    criteria = [
        {"key": "dmarc_record", "ok": bool(check) and not any(f["check"] == "dmarc" and f["severity"] == "error" for f in findings),
         "text": "Exactly one valid DMARC record is published."},
        {"key": "reports", "ok": bool(dmarc.get("rua")), "text": "Aggregate reports (rua) are being requested."},
        {"key": "spf", "ok": bool(check) and not any(f["check"] == "spf" and f["severity"] == "error" for f in findings),
         "text": "The SPF record is valid (one record, at most 10 lookups)."},
        {"key": "data", "ok": report_days >= s.min_report_days,
         "text": f"At least {s.min_report_days} days of reports (now {report_days})."},
        {"key": "pass_rate", "ok": pass_rate is not None and pass_rate >= s.reject_ready_pass_rate,
         "text": f"At least {s.reject_ready_pass_rate:g}% of legitimate, non-forwarded mail passes DMARC "
                 f"(now {pass_rate if pass_rate is not None else '-'}%)."},
        {"key": "senders", "ok": not failing_legit,
         "text": "No legitimate sender has a significant share of failing mail"
                 + (f" (now: {', '.join(x.name for x in failing_legit[:3])})." if failing_legit else ".")},
    ]
    failed = [c for c in criteria if not c["ok"]]
    if not failed:
        status = "ready"
    elif all(c["key"] in ("data", "pass_rate", "senders") for c in failed) and (pass_rate or 0) >= 90:
        status = "almost"
    else:
        status = "not_ready"

    return {
        "domain": domain, "status": status, "policy": policy, "pct": pct, "pass_rate": pass_rate,
        "legit_messages": legit_msgs, "total_messages": sum(x.messages for x in sources),
        "report_days": report_days, "criteria": criteria,
        "unknown_failing": [{"key": x.key, "name": x.name, "messages": x.failing} for x in unknown_failing[:10]],
        "next_step": _next_step(domain, status, policy, pct, dmarc),
    }


def _next_step(domain: str, status: str, policy: str | None, pct: int, dmarc: dict) -> dict[str, Any] | None:
    rua = ",".join(f"mailto:{a}" for a in dmarc.get("rua", [])) or "mailto:<report address>"
    base = f"_dmarc.{domain}"
    if policy == "reject" and pct >= 100:
        return None
    if status != "ready":
        return None
    if policy in (None, "none"):
        return {"title": f"{domain} is ready for p=quarantine",
                "text": "All legitimate senders pass DMARC. Start enforcing gradually and keep watching the reports.",
                "actions": [f'Set {base} to "v=DMARC1; p=quarantine; pct=25; rua={rua}", after a week pct=100.']}
    if policy == "quarantine" and pct < 100:
        return {"title": f"Increase pct for {domain} to 100",
                "text": "Quarantine is only applied to part of the failing mail.",
                "actions": [f'Set {base} to "v=DMARC1; p=quarantine; rua={rua}".']}
    return {"title": f"{domain} is ready for p=reject",
            "text": "Reports show no legitimate mail failing DMARC under p=quarantine.",
            "actions": [f'Set {base} to "v=DMARC1; p=reject; rua={rua}".']}
