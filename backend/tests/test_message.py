import pytest

from dmarc.parsing.message import parse_email, parse_file
from tests.conftest import fixture_bytes


@pytest.mark.parametrize("name,org,records", [
    ("google.eml", "google.com", 3),        # zip attachment
    ("microsoft.eml", "Enterprise Outlook", 2),  # .xml.gz, application/gzip
    ("yahoo.eml", "Yahoo", 1),              # .xml.gz labelled application/octet-stream
    ("mailru.eml", "Mail.Ru", 1),           # application/x-gzip, RFC 2047 subject
    ("quirky.eml", "Quirky Mail Corp", 1),  # plain text/xml attachment
    ("inline.eml", "Yahoo", 1),             # XML in the body, no attachment
])
def test_report_emails(name, org, records, settings):
    p = parse_email(fixture_bytes("rua", name), settings)
    assert p.ok and p.kind == "rua", p.errors
    [r] = p.aggregate
    assert r.org_name == org and len(r.records) == records
    assert p.aggregate_raw[0].lstrip().startswith(b"<")


def test_rfc2047_subject_decoded(settings):
    assert parse_email(fixture_bytes("rua", "mailru.eml"), settings).subject == "Report Domain: example.com"


@pytest.mark.parametrize("name,count", [("multi.zip", 2), ("nested.zip", 1), ("dmarcbis.xml.gz", 1)])
def test_bare_files(name, count, settings):
    p = parse_file(fixture_bytes("rua", name), name, settings)
    assert p.ok and len(p.aggregate) == count


def test_bare_eml_via_parse_file(settings):
    assert parse_file(fixture_bytes("rua", "google.eml"), "google.eml", settings).kind == "rua"


def test_forensic_email(settings):
    settings.ruf_store_body = False
    p = parse_email(fixture_bytes("ruf", "arf_full.eml"), settings)
    assert p.kind == "ruf" and p.ok and p.forensic[0].original_body is None


def test_forensic_body_setting(settings):
    settings.ruf_store_body = True
    p = parse_email(fixture_bytes("ruf", "arf_full.eml"), settings)
    assert b"IBAN" in p.forensic[0].original_body


def test_mixed_good_and_bad_attachment(settings):
    p = parse_email(fixture_bytes("broken", "mixed.eml"), settings)
    assert len(p.aggregate) == 1 and len(p.errors) == 1 and not p.ok
    assert "bad.xml" in p.errors[0]


@pytest.mark.parametrize("name,msg", [
    ("no_report.eml", "no DMARC report"),
    ("pdf_named_zip.eml", "not XML, gzip or zip"),
    ("arf_no_feedback_type.eml", "Feedback-Type"),
])
def test_unusable_messages(name, msg, settings):
    p = parse_email(fixture_bytes("broken", name), settings)
    assert p.kind == "none" and not p.ok
    assert any(msg in e for e in p.errors)


def test_message_size_limit(settings):
    settings.max_message_bytes = 100
    p = parse_email(fixture_bytes("rua", "google.eml"), settings)
    assert not p.ok and "exceeds limit" in p.errors[0]


def test_truncated_inline(settings):
    raw = fixture_bytes("rua", "inline.eml")
    cut = raw[: raw.index(b"</feedback>")]
    p = parse_email(cut, settings)
    assert not p.ok and "truncated" in p.errors[0]
