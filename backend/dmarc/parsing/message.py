"""Classify an incoming e-mail (or a bare report file) and extract the reports in it."""

from __future__ import annotations

import email
import email.policy
from dataclasses import dataclass, field
from email.message import Message

from dmarc.config import Settings, get_settings
from dmarc.parsing.extract import ExtractionError, LimitExceeded, Payload, extract_payloads, sniff
from dmarc.parsing.ruf import ForensicParseError, ForensicReport, decode_header_value, find_feedback_part, parse_forensic
from dmarc.parsing.rua import AggregateReport, ReportParseError, parse_aggregate

REPORT_CONTENT_TYPES = {
    "application/zip",
    "application/x-zip",
    "application/x-zip-compressed",
    "application/gzip",
    "application/x-gzip",
    "application/x-gunzip",
    "application/gzip-compressed",
    "application/xml",
    "text/xml",
    "application/octet-stream",
}


@dataclass
class ParsedMessage:
    subject: str | None = None
    sender: str | None = None
    message_id: str | None = None
    aggregate: list[AggregateReport] = field(default_factory=list)
    forensic: list[ForensicReport] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # The raw XML payload belonging to each aggregate report (same index).
    aggregate_raw: list[bytes] = field(default_factory=list)

    @property
    def kind(self) -> str:
        if self.forensic:
            return "ruf"
        if self.aggregate:
            return "rua"
        return "none"

    @property
    def ok(self) -> bool:
        return bool(self.aggregate or self.forensic) and not self.errors


def _parse_payloads(payloads: list[Payload], result: ParsedMessage) -> None:
    for p in payloads:
        try:
            result.aggregate.append(parse_aggregate(p.data))
            result.aggregate_raw.append(p.data)
        except ReportParseError as exc:
            result.errors.append(f"{p.name}: {exc}")


def _handle_blob(data: bytes, name: str, result: ParsedMessage, s: Settings) -> None:
    try:
        _parse_payloads(extract_payloads(data, name, s), result)
    except (ExtractionError, LimitExceeded) as exc:
        result.errors.append(str(exc))


def parse_file(data: bytes, name: str = "report", settings: Settings | None = None) -> ParsedMessage:
    """Parse a bare .xml/.gz/.zip file or a raw RFC 5322 e-mail (.eml)."""
    s = settings or get_settings()
    if sniff(data) != "unknown":
        result = ParsedMessage()
        _handle_blob(data, name, result, s)
        return result
    return parse_email(data, s)


def parse_email(raw: bytes, settings: Settings | None = None) -> ParsedMessage:
    s = settings or get_settings()
    result = ParsedMessage()
    if len(raw) > s.max_message_bytes:
        result.errors.append(f"message of {len(raw)} bytes exceeds limit of {s.max_message_bytes}")
        return result

    msg: Message = email.message_from_bytes(raw, policy=email.policy.compat32)
    result.subject = decode_header_value(msg.get("Subject")) or None
    result.sender = decode_header_value(msg.get("From")) or None
    result.message_id = (msg.get("Message-ID") or "").strip() or None

    # 1. Forensic report (ARF)?
    if find_feedback_part(msg) is not None:
        try:
            result.forensic.append(parse_forensic(msg, store_body=s.ruf_store_body))
        except ForensicParseError as exc:
            result.errors.append(f"forensic report: {exc}")
        return result

    # 2. Aggregate report attachments
    found_attachment = False
    for part in msg.walk():
        if part.is_multipart() or part.get_content_maintype() == "message":
            continue
        filename = decode_header_value(part.get_filename()) if part.get_filename() else None
        ctype = part.get_content_type()
        disposition = (part.get("Content-Disposition") or "").lower()
        is_candidate = (
            ctype in REPORT_CONTENT_TYPES
            or "attachment" in disposition
            or bool(filename and filename.lower().endswith((".xml", ".gz", ".zip", ".gzip")))
        )
        if not is_candidate:
            continue
        data = part.get_payload(decode=True)
        if not isinstance(data, bytes) or not data:
            continue
        if sniff(data) == "unknown":
            # Signatures, logos, etc.; only complain if it really looked like a report.
            if filename and filename.lower().endswith((".xml", ".gz", ".zip")):
                result.errors.append(f"{filename}: attachment is not XML, gzip or zip data")
            continue
        found_attachment = True
        _handle_blob(data, filename or f"part.{part.get_content_subtype()}", result, s)

    if found_attachment:
        return result

    # 3. Inline XML in the body
    for part in msg.walk():
        if part.get_content_maintype() != "text":
            continue
        body = part.get_payload(decode=True)
        if isinstance(body, bytes) and b"<feedback" in body:
            start = body.find(b"<?xml")
            if start < 0:
                start = body.find(b"<feedback")
            end = body.rfind(b"</feedback>")
            if end < 0:
                result.errors.append("inline XML report is truncated (no </feedback>)")
                return result
            _parse_payloads([Payload("inline-body.xml", body[start : end + len(b"</feedback>")])], result)
            return result

    result.errors.append("no DMARC report found in message")
    return result
