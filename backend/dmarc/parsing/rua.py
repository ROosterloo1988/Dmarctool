"""Parser for DMARC aggregate reports (RUA).

Follows RFC 7489 appendix C and is tolerant for:
- the DMARCbis schema (``urn:ietf:params:xml:ns:dmarc-2.0`` namespace, ``np``,
  ``testing``, ``discovery_method``, ``generator``),
- arbitrary/missing namespaces and odd tag casing,
- missing optional elements (header_from, count, policy fields),
- whitespace, IPv6 and IPv4-mapped addresses, ISO-8601 instead of epoch timestamps,
- mislabelled encodings in the XML declaration.

XML is parsed with defusedxml: entity expansion and external entities are refused.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from xml.etree.ElementTree import Element, ParseError

import defusedxml.ElementTree as SafeET
from defusedxml import DefusedXmlException

from dmarc.parsing.alignment import is_aligned, normalize_domain


class ReportParseError(Exception):
    """The payload is not a usable DMARC aggregate report."""


@dataclass
class DkimResult:
    domain: str | None
    selector: str | None
    result: str
    human_result: str | None = None


@dataclass
class SpfResult:
    domain: str | None
    scope: str | None
    result: str


@dataclass
class Record:
    source_ip: str
    count: int
    disposition: str | None
    policy_dkim: str | None  # as evaluated by the reporter
    policy_spf: str | None
    reasons: list[dict[str, str | None]]
    header_from: str | None
    envelope_from: str | None
    envelope_to: str | None
    dkim: list[DkimResult]
    spf: list[SpfResult]
    # Calculated by us from auth results + published policy:
    dkim_aligned: bool = False
    spf_aligned: bool = False
    dmarc_pass: bool = False


@dataclass
class PolicyPublished:
    domain: str
    adkim: str = "r"
    aspf: str = "r"
    p: str | None = None
    sp: str | None = None
    np: str | None = None
    pct: int | None = None
    fo: str | None = None
    testing: str | None = None


@dataclass
class AggregateReport:
    org_name: str
    email: str | None
    extra_contact_info: str | None
    report_id: str
    date_begin: datetime
    date_end: datetime
    errors: list[str]
    policy: PolicyPublished
    records: list[Record] = field(default_factory=list)
    version: str | None = None
    generator: str | None = None

    @property
    def domain(self) -> str:
        return self.policy.domain

    @property
    def message_count(self) -> int:
        return sum(r.count for r in self.records)


# --------------------------------------------------------------------------------------
# XML helpers
# --------------------------------------------------------------------------------------

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""


def _strip_namespaces(root: Element) -> None:
    for el in root.iter():
        el.tag = _local(el.tag)


def _child(el: Element | None, name: str) -> Element | None:
    if el is None:
        return None
    return el.find(name)


def _children(el: Element | None, name: str) -> list[Element]:
    return [] if el is None else el.findall(name)


def _text(el: Element | None, *path: str) -> str | None:
    node = el
    for p in path:
        node = _child(node, p)
        if node is None:
            return None
    if node is None or node.text is None:
        return None
    t = node.text.strip()
    return t or None


_XML_DECL = re.compile(rb"^\s*<\?xml[^>]*\?>", re.IGNORECASE)


def _parse_xml(data: bytes) -> Element:
    try:
        return SafeET.fromstring(data, forbid_dtd=False, forbid_entities=True, forbid_external=True)
    except DefusedXmlException as exc:
        raise ReportParseError(f"unsafe XML refused: {type(exc).__name__}") from exc
    except ParseError as first:
        # Common reporter bug: declared encoding does not match the bytes, or junk before
        # the root element. Retry once on a cleaned-up UTF-8 version.
        text = _XML_DECL.sub(b"", data.lstrip(b"\xef\xbb\xbf")).decode("utf-8", errors="replace")
        start = text.find("<")
        if start < 0:
            raise ReportParseError(f"invalid XML: {first}") from first
        try:
            return SafeET.fromstring(text[start:], forbid_dtd=False, forbid_entities=True, forbid_external=True)
        except DefusedXmlException as exc:
            raise ReportParseError(f"unsafe XML refused: {type(exc).__name__}") from exc
        except ParseError as exc:
            raise ReportParseError(f"invalid XML: {exc}") from exc


def _parse_time(value: str | None, what: str) -> datetime:
    if value is None:
        raise ReportParseError(f"missing {what}")
    v = value.strip()
    try:
        return datetime.fromtimestamp(int(float(v)), tz=UTC)
    except (ValueError, OverflowError, OSError):
        pass
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError as exc:
        raise ReportParseError(f"unparseable {what}: {value!r}") from exc


def _parse_int(value: str | None, default: int | None = None) -> int | None:
    if value is None:
        return default
    try:
        return int(float(value.strip()))
    except ValueError:
        return default


def _normalize_ip(value: str | None) -> str:
    if not value:
        raise ReportParseError("record without source_ip")
    v = value.strip().strip("[]")
    try:
        ip = ipaddress.ip_address(v)
    except ValueError as exc:
        raise ReportParseError(f"invalid source_ip {value!r}") from exc
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def _lower(v: str | None) -> str | None:
    return v.lower() if v else v


# --------------------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------------------

def parse_aggregate(data: bytes) -> AggregateReport:
    root = _parse_xml(data)
    _strip_namespaces(root)

    # Some reporters wrap <feedback> in another element.
    if root.tag != "feedback":
        inner = root.find(".//feedback")
        if inner is None:
            raise ReportParseError(f"root element is <{root.tag}>, expected <feedback>")
        root = inner

    meta = _child(root, "report_metadata")
    pol = _child(root, "policy_published")
    if meta is None:
        raise ReportParseError("missing report_metadata")
    if pol is None:
        raise ReportParseError("missing policy_published")

    org_name = _text(meta, "org_name")
    report_id = _text(meta, "report_id")
    if not org_name:
        raise ReportParseError("missing org_name")
    if not report_id:
        raise ReportParseError("missing report_id")

    begin = _parse_time(_text(meta, "date_range", "begin"), "date_range/begin")
    end = _parse_time(_text(meta, "date_range", "end"), "date_range/end")

    domain = normalize_domain(_text(pol, "domain"))
    if not domain:
        raise ReportParseError("missing policy_published/domain")

    policy = PolicyPublished(
        domain=domain,
        adkim=(_lower(_text(pol, "adkim")) or "r")[:1],
        aspf=(_lower(_text(pol, "aspf")) or "r")[:1],
        p=_lower(_text(pol, "p")),
        sp=_lower(_text(pol, "sp")),
        np=_lower(_text(pol, "np")),
        pct=_parse_int(_text(pol, "pct")),
        fo=_text(pol, "fo"),
        testing=_lower(_text(pol, "testing")),
    )

    report = AggregateReport(
        org_name=org_name,
        email=_text(meta, "email"),
        extra_contact_info=_text(meta, "extra_contact_info"),
        report_id=report_id,
        date_begin=begin,
        date_end=end,
        errors=[e.text.strip() for e in _children(meta, "error") if e.text and e.text.strip()],
        policy=policy,
        version=_text(root, "version"),
        generator=_text(meta, "generator"),
    )

    for rec in _children(root, "record"):
        report.records.append(_parse_record(rec, policy))

    return report


def _parse_record(rec: Element, policy: PolicyPublished) -> Record:
    row = _child(rec, "row")
    pe = _child(row, "policy_evaluated")
    ids = _child(rec, "identifiers")
    auth = _child(rec, "auth_results")

    reasons = [
        {"type": _lower(_text(r, "type")), "comment": _text(r, "comment")}
        for r in _children(pe, "reason")
    ]

    dkim = [
        DkimResult(
            domain=normalize_domain(_text(d, "domain")),
            selector=_text(d, "selector"),
            result=_lower(_text(d, "result")) or "none",
            human_result=_text(d, "human_result"),
        )
        for d in _children(auth, "dkim")
    ]
    spf = [
        SpfResult(
            domain=normalize_domain(_text(s, "domain")),
            scope=_lower(_text(s, "scope")),
            result=_lower(_text(s, "result")) or "none",
        )
        for s in _children(auth, "spf")
    ]

    header_from = normalize_domain(_text(ids, "header_from")) or policy.domain
    envelope_from = normalize_domain(_text(ids, "envelope_from"))

    r = Record(
        source_ip=_normalize_ip(_text(row, "source_ip")),
        count=_parse_int(_text(row, "count"), 1) or 0,
        disposition=_lower(_text(pe, "disposition")),
        policy_dkim=_lower(_text(pe, "dkim")),
        policy_spf=_lower(_text(pe, "spf")),
        reasons=reasons,
        header_from=header_from,
        envelope_from=envelope_from,
        envelope_to=normalize_domain(_text(ids, "envelope_to")),
        dkim=dkim,
        spf=spf,
    )
    _compute_alignment(r, policy)
    return r


def _compute_alignment(r: Record, policy: PolicyPublished) -> None:
    """Determine alignment ourselves; fall back to the reporter's verdict if no auth results."""
    r.dkim_aligned = any(
        d.result == "pass" and is_aligned(d.domain, r.header_from, policy.adkim) for d in r.dkim
    )
    # Only the MAIL FROM identity counts for DMARC; HELO-scoped results are ignored.
    # If no envelope domain is reported for SPF, some reporters (e.g. Microsoft) still
    # report the MAIL FROM domain as envelope_from.
    spf_candidates = [s for s in r.spf if s.scope in (None, "mfrom")]
    r.spf_aligned = any(
        s.result == "pass" and is_aligned(s.domain or r.envelope_from, r.header_from, policy.aspf)
        for s in spf_candidates
    )
    if not r.dkim:
        r.dkim_aligned = r.policy_dkim == "pass"
    if not r.spf:
        r.spf_aligned = r.policy_spf == "pass"
    r.dmarc_pass = r.dkim_aligned or r.spf_aligned
