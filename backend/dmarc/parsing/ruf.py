"""Parser for DMARC failure/forensic reports (RUF) in ARF format (RFC 5965, RFC 6591).

Privacy: by default only the headers of the original message are kept. The body is
only returned when ``store_body`` is True (configurable, see Settings.ruf_store_body).
"""

from __future__ import annotations

import base64
import binascii
import email
import email.header
import email.parser
import email.utils
import ipaddress
import quopri
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import Message

from dmarc.parsing.alignment import normalize_domain

MAX_HEADERS = 500
MAX_BODY_BYTES = 1024 * 1024


class ForensicParseError(Exception):
    """The message is not a usable ARF failure report."""


@dataclass
class ForensicReport:
    feedback_type: str
    user_agent: str | None
    version: str | None
    arrival_date: datetime | None
    source_ip: str | None
    reported_domain: str | None
    original_mail_from: str | None
    original_rcpt_to: list[str]
    auth_failure: str | None
    delivery_result: str | None
    authentication_results: str | None
    dkim_domain: str | None
    dkim_selector: str | None
    dkim_identity: str | None
    spf_dns: str | None
    identity_alignment: str | None
    reporter: str | None  # From: of the report e-mail
    report_message_id: str | None
    # Original message (headers always, body only on request)
    original_headers: list[tuple[str, str]] = field(default_factory=list)
    original_subject: str | None = None
    original_from: str | None = None
    original_to: str | None = None
    original_message_id: str | None = None
    original_date: datetime | None = None
    original_body: bytes | None = None
    feedback_fields: dict[str, list[str]] = field(default_factory=dict)

    @property
    def header_from_domain(self) -> str | None:
        if self.original_from:
            _, addr = email.utils.parseaddr(self.original_from)
            return normalize_domain(addr) if addr else None
        return None


def decode_header_value(value: object) -> str:
    if value is None:
        return ""
    try:
        return str(email.header.make_header(email.header.decode_header(str(value)))).strip()
    except (email.errors.HeaderParseError, UnicodeError, LookupError, ValueError):
        return str(value).strip()


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        try:
            dt = datetime.fromisoformat(value.strip())
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def _part_bytes(part: Message) -> bytes:
    """Decoded content of a part, also for message/* parts that carry a transfer encoding.

    The email package parses message/* payloads into sub-messages even when they are
    base64/quoted-printable encoded (which RFC 2046 forbids, but reporters do it), and
    then refuses to decode them. Re-serialise the body and decode it ourselves.
    """
    payload = part.get_payload(decode=True)
    if isinstance(payload, bytes):
        return payload
    raw = part.get_payload()
    if isinstance(raw, list):
        data = b"".join(p.as_bytes() for p in raw if isinstance(p, Message))
    else:
        data = str(raw or "").encode("utf-8", errors="replace")
    cte = (part.get("Content-Transfer-Encoding") or "").strip().lower()
    try:
        if cte == "base64":
            return base64.b64decode(b"".join(data.split()), validate=False)
        if cte == "quoted-printable":
            return quopri.decodestring(data)
    except (binascii.Error, ValueError):
        pass
    return data


def _is_transfer_encoded(part: Message) -> bool:
    return (part.get("Content-Transfer-Encoding") or "").strip().lower() in ("base64", "quoted-printable")


def _as_header_message(part: Message) -> Message:
    """Return a Message whose headers are the fields of a header-block style part.

    Handles message/* parts that the email package already parsed into a sub-message,
    and text/* or base64-encoded parts that need to be parsed here.
    """
    payload = part.get_payload()
    if isinstance(payload, list) and payload and isinstance(payload[0], Message) and not _is_transfer_encoded(part):
        return payload[0]
    return email.parser.BytesParser().parsebytes(_part_bytes(part), headersonly=True)


def find_feedback_part(msg: Message) -> Message | None:
    for part in msg.walk():
        if part.get_content_type() == "message/feedback-report":
            return part
    return None


def parse_forensic(msg: Message, store_body: bool = False) -> ForensicReport:
    fb_part = find_feedback_part(msg)
    if fb_part is None:
        raise ForensicParseError("no message/feedback-report part")

    fb = _as_header_message(fb_part)
    fields: dict[str, list[str]] = {}
    for k, v in fb.items():
        fields.setdefault(k.lower(), []).append(decode_header_value(v))

    def one(name: str) -> str | None:
        vals = fields.get(name)
        return vals[0] if vals else None

    feedback_type = (one("feedback-type") or "").lower()
    if not feedback_type:
        raise ForensicParseError("feedback report without Feedback-Type")

    report = ForensicReport(
        feedback_type=feedback_type,
        user_agent=one("user-agent"),
        version=one("version"),
        arrival_date=_parse_date(one("arrival-date") or one("received-date")),
        source_ip=_ip(one("source-ip")),
        reported_domain=normalize_domain(one("reported-domain")),
        original_mail_from=one("original-mail-from"),
        original_rcpt_to=fields.get("original-rcpt-to", []),
        auth_failure=(one("auth-failure") or "").lower() or None,
        delivery_result=(one("delivery-result") or "").lower() or None,
        authentication_results=one("authentication-results"),
        dkim_domain=normalize_domain(one("dkim-domain")),
        dkim_selector=one("dkim-selector"),
        dkim_identity=one("dkim-identity"),
        spf_dns=one("spf-dns"),
        identity_alignment=one("identity-alignment"),
        reporter=decode_header_value(msg.get("From")) or None,
        report_message_id=(msg.get("Message-ID") or "").strip() or None,
        feedback_fields=fields,
    )

    original = _find_original(msg)
    if original is not None:
        headers_msg, body = original
        report.original_headers = [(k, decode_header_value(v)) for k, v in list(headers_msg.items())[:MAX_HEADERS]]
        report.original_subject = decode_header_value(headers_msg.get("Subject")) or None
        report.original_from = decode_header_value(headers_msg.get("From")) or None
        report.original_to = decode_header_value(headers_msg.get("To")) or None
        report.original_message_id = (headers_msg.get("Message-ID") or "").strip() or None
        report.original_date = _parse_date(headers_msg.get("Date"))
        if store_body and body is not None:
            report.original_body = body[:MAX_BODY_BYTES]

    if report.reported_domain is None:
        report.reported_domain = report.header_from_domain
    return report


def _find_original(msg: Message) -> tuple[Message, bytes | None] | None:
    """Locate the returned original message (message/rfc822) or its headers (text/rfc822-headers)."""
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype == "message/rfc822":
            payload = part.get_payload()
            if isinstance(payload, list) and payload and isinstance(payload[0], Message):
                inner = payload[0]
                if _is_transfer_encoded(part):
                    inner = email.message_from_bytes(_part_bytes(part))
                return inner, _body_bytes(inner)
        if ctype == "text/rfc822-headers":
            return email.parser.BytesParser().parsebytes(_part_bytes(part), headersonly=True), None
    return None


def _body_bytes(m: Message) -> bytes:
    raw = m.as_bytes()
    sep = raw.find(b"\n\n")
    return raw[sep + 2 :] if sep >= 0 else b""
