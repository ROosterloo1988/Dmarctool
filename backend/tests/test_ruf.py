import email
from datetime import UTC, datetime

import pytest

from dmarc.parsing.ruf import ForensicParseError, parse_forensic
from tests.conftest import fixture_bytes


def load(*p):
    return email.message_from_bytes(fixture_bytes(*p))


def test_full_arf_headers_only_by_default():
    r = parse_forensic(load("ruf", "arf_full.eml"))
    assert r.feedback_type == "auth-failure" and r.auth_failure == "dmarc"
    assert r.source_ip == "203.0.113.66" and r.reported_domain == "example.com"
    assert r.arrival_date == datetime(2025, 11, 24, 10, 15, 2, tzinfo=UTC)
    assert r.original_rcpt_to == ["<victim@receiver.example>"]
    assert r.delivery_result == "delivered"
    assert r.original_subject == "Urgent invoice"
    assert r.original_message_id == "<spoof-123@spoofer.example>"
    assert r.header_from_domain == "example.com"
    assert ("Subject", "Urgent invoice") in r.original_headers
    assert r.original_body is None  # privacy default


def test_full_arf_body_when_enabled():
    r = parse_forensic(load("ruf", "arf_full.eml"), store_body=True)
    assert b"IBAN" in r.original_body


def test_headers_only_arf():
    r = parse_forensic(load("ruf", "arf_headers_only.eml"), store_body=True)
    assert r.original_from == '"Finance" <finance@example.com>'
    assert r.original_body is None and r.delivery_result is None


def test_base64_encoded_feedback_part():
    r = parse_forensic(load("ruf", "arf_base64.eml"))
    assert r.feedback_type == "auth-failure" and r.source_ip == "203.0.113.66"
    assert r.original_subject == "Urgent invoice"


def test_missing_feedback_type():
    with pytest.raises(ForensicParseError, match="Feedback-Type"):
        parse_forensic(load("broken", "arf_no_feedback_type.eml"))


def test_not_an_arf_message():
    with pytest.raises(ForensicParseError):
        parse_forensic(load("broken", "no_report.eml"))
