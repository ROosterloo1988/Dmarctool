import gzip
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from dmarc.db import models as m
from dmarc.storage import ingest_email, ingest_file, purge_expired
from tests.conftest import fixture_bytes


def count(session, model):
    return session.scalar(select(func.count()).select_from(model))


def test_import_google_report(session, settings):
    out = ingest_email(session, fixture_bytes("rua", "google.eml"), external_id="graph-1", settings=settings)
    session.commit()
    assert (out.status, out.kind, out.new, out.duplicate) == ("processed", "rua", 1, 0)

    rep = session.scalars(select(m.AggregateReport)).one()
    assert (rep.org_name, rep.report_id, rep.domain, rep.message_count) == ("google.com", "13190401177745345981", "example.com", 1615)
    assert b"<feedback>" in gzip.decompress(rep.raw_xml_gz)
    assert rep.inbound_message_id == out.inbound_message_id

    recs = {str(r.source_ip): r for r in rep.records}
    assert recs["2a01:111:f403:c201::1"].dmarc_pass
    assert not recs["198.51.100.23"].dmarc_pass
    dkim = [a for a in recs["2a01:111:f403:c201::1"].auth_results if a.method == "dkim"]
    assert dkim[0].selector == "selector1" and dkim[0].aligned
    assert count(session, m.AuthResult) == 5

    inbound = session.get(m.InboundMessage, out.inbound_message_id)
    assert inbound.subject.startswith("Report domain: example.com") and inbound.status == "processed"


def test_reimport_is_idempotent(session, settings):
    raw = fixture_bytes("rua", "google.eml")
    ingest_email(session, raw, external_id="graph-1", settings=settings)
    session.commit()
    # Same report delivered again as a different e-mail, and the same e-mail re-processed.
    out2 = ingest_email(session, raw, external_id="graph-2", settings=settings)
    out3 = ingest_email(session, raw, external_id="graph-1", settings=settings)
    session.commit()
    assert out2.status == out3.status == "duplicate"
    assert count(session, m.AggregateReport) == 1
    assert count(session, m.AggregateRecord) == 3
    assert count(session, m.InboundMessage) == 2  # graph-1 row updated, not duplicated


def test_same_report_id_other_domain_is_distinct(session, settings):
    xml = fixture_bytes("src", "yahoo.xml")
    ingest_file(session, xml, "a.xml", settings)
    out = ingest_file(session, xml.replace(b"<domain>example.com</domain>", b"<domain>example.org</domain>"), "b.xml", settings)
    session.commit()
    assert out.status == "processed" and count(session, m.AggregateReport) == 2


def test_zip_with_multiple_reports(session, settings):
    out = ingest_file(session, fixture_bytes("rua", "multi.zip"), "multi.zip", settings)
    session.commit()
    assert out.new == 2 and count(session, m.AggregateReport) == 2


def test_partial_message_keeps_good_report(session, settings):
    out = ingest_email(session, fixture_bytes("broken", "mixed.eml"), external_id="mixed", settings=settings)
    session.commit()
    assert out.status == "partial" and out.new == 1 and len(out.errors) == 1
    assert count(session, m.AggregateReport) == 1
    inbound = session.get(m.InboundMessage, out.inbound_message_id)
    assert inbound.errors and "bad.xml" in inbound.errors[0]


def test_failed_message_is_logged(session, settings):
    out = ingest_email(session, fixture_bytes("broken", "no_report.eml"), external_id="lunch", settings=settings)
    session.commit()
    assert out.status == "failed" and out.kind == "none"
    row = session.get(m.InboundMessage, out.inbound_message_id)
    assert row.status == "failed" and row.subject == "Lunch?"


def test_unexpected_parser_crash_does_not_raise(session, settings, monkeypatch):
    import dmarc.storage

    def boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(dmarc.storage, "parse_email", boom)
    out = ingest_email(session, b"whatever", external_id="x", settings=settings)
    assert out.status == "failed" and "kaboom" in out.errors[0]


def test_raw_xml_storage_can_be_disabled(session, settings):
    settings.rua_store_raw_xml = False
    ingest_file(session, fixture_bytes("rua", "dmarcbis.xml.gz"), "d.xml.gz", settings)
    session.commit()
    assert session.scalars(select(m.AggregateReport)).one().raw_xml_gz is None


def test_forensic_storage_and_privacy(session, settings):
    out = ingest_email(session, fixture_bytes("ruf", "arf_full.eml"), external_id="ruf-1", settings=settings)
    again = ingest_email(session, fixture_bytes("ruf", "arf_full.eml"), external_id="ruf-1b", settings=settings)
    session.commit()
    assert out.status == "processed" and again.status == "duplicate"
    fr = session.scalars(select(m.ForensicReport)).one()
    assert str(fr.source_ip) == "203.0.113.66" and fr.reported_domain == "example.com"
    assert fr.original_body is None and fr.original_subject == "Urgent invoice"
    assert timedelta(days=29) < fr.expires_at - datetime.now(UTC) <= timedelta(days=30)


def test_forensic_body_stored_when_enabled(session, settings):
    settings.ruf_store_body = True
    ingest_email(session, fixture_bytes("ruf", "arf_full.eml"), settings=settings)
    session.commit()
    assert b"IBAN" in session.scalars(select(m.ForensicReport)).one().original_body


def test_purge(session, settings):
    ingest_email(session, fixture_bytes("ruf", "arf_full.eml"), settings=settings)
    ingest_email(session, fixture_bytes("rua", "google.eml"), settings=settings)  # period Nov 2025
    session.commit()
    now = datetime.now(UTC)
    assert purge_expired(session, settings, now) == {"forensic_deleted": 0, "aggregate_deleted": 0}
    result = purge_expired(session, settings, now + timedelta(days=800))
    session.commit()
    assert result == {"forensic_deleted": 1, "aggregate_deleted": 1}
    assert count(session, m.AggregateRecord) == 0 and count(session, m.AuthResult) == 0
