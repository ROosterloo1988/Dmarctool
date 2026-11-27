from datetime import UTC, date, datetime

import pytest
from sqlalchemy import select

from dmarc.analysis import readiness, recommendations, source_overview
from dmarc.db import models as m
from dmarc.dnscheck.run import run_dns_checks, selectors_for
from dmarc.enrich import assign_sources, enrich_ips
from dmarc.geoip import GeoIp
from dmarc.senders import load_catalog
from dmarc.stats import rebuild_daily
from dmarc.storage import ingest_email
from tests.conftest import fixture_bytes

NOW = datetime(2025, 11, 26, 12, 0, tzinfo=UTC)


@pytest.fixture
def loaded(session, settings, fake_dns, geoip_files):
    for name in ("google.eml", "microsoft.eml", "yahoo.eml"):
        ingest_email(session, fixture_bytes("rua", name), settings=settings)
    session.add(m.Domain(name="example.com"))
    session.commit()
    settings.geoip_dir = str(geoip_files)
    geo = GeoIp.from_settings(settings)
    catalog = load_catalog()
    assert enrich_ips(session, fake_dns, geo, catalog, settings, NOW) == 6
    assign_sources(session, catalog)
    run_dns_checks(session, settings, fake_dns, NOW)
    session.commit()
    return catalog


def info(session, ip):
    return session.get(m.IpInfo, ip)


def test_ip_enrichment(loaded, session):
    ms = info(session, "40.107.22.105")
    assert (ms.ptr_confirmed, ms.asn, ms.as_org, ms.country, ms.sender_key) == (True, 8075, "Microsoft Corporation", "IE", "microsoft365")
    assert info(session, "198.51.100.23").sender_key == "flowmailer"
    spoof = info(session, "203.0.113.77")
    assert spoof.ptr == "fake.flowmailer.net" and not spoof.ptr_confirmed and spoof.sender_key is None
    assert info(session, "209.85.220.41").sender_key == "google_workspace"
    assert info(session, "192.0.2.10").ptr is None and info(session, "192.0.2.10").asn == 64502


def test_enrichment_is_incremental(loaded, session, settings, fake_dns, geoip_files):
    geo = GeoIp.from_settings(settings)
    assert enrich_ips(session, fake_dns, geo, loaded, settings, NOW) == 0  # all fresh
    later = datetime(2026, 1, 15, tzinfo=UTC)
    assert enrich_ips(session, fake_dns, geo, loaded, settings, later) == 6  # stale after 30 days


def test_source_keys(loaded, session):
    keys = {str(r.source_ip): r.source_key for r in session.scalars(select(m.AggregateRecord))}
    assert keys == {
        "2a01:111:f403:c201::1": "sender:microsoft365",
        "40.107.22.105": "sender:microsoft365",
        "198.51.100.23": "sender:flowmailer",
        "203.0.113.77": "asn:64500",
        "209.85.220.41": "sender:google_workspace",
        "192.0.2.10": "asn:64502",
    }


def test_daily_rollup(loaded, session):
    rebuild_daily(session, date(2025, 1, 1), loaded)
    rows = {r.source_key: r for r in session.scalars(select(m.DailyStat))}
    ms = rows["sender:microsoft365"]
    assert (ms.day, ms.messages, ms.dmarc_pass, ms.source_name) == (date(2025, 11, 24), 499, 499, "Microsoft 365 (Exchange Online)")
    fm = rows["sender:flowmailer"]
    assert (fm.messages, fm.dmarc_pass, fm.spf_pass, fm.dkim_pass, fm.spf_aligned) == (1200, 0, 1200, 1200, 0)
    assert rows["asn:64500"].source_name == "Example Bulletproof Hosting (AS64500)"
    assert rows["sender:google_workspace"].forwarded == 2  # forwarded (still passing via DKIM)
    # Rebuilding is idempotent
    rebuild_daily(session, date(2025, 1, 1), loaded)
    assert len(session.scalars(select(m.DailyStat)).all()) == len(rows)


def test_dns_check_stored_with_selectors(loaded, session):
    assert selectors_for(session, "example.com", now=NOW) == [("example.com", "selector1"), ("example.com", "selector2")]
    check = session.scalars(select(m.DnsCheck)).one()
    codes = {f["code"] for f in check.findings}
    assert {"dmarc.p_none", "spf.fail_all", "dkim.selector_missing"} <= codes
    assert check.result["spf"]["includes"] == ["spf.protection.outlook.com"]


def test_source_overview(loaded, session, settings):
    sources = {s.key: s for s in source_overview(session, "example.com", now=NOW, settings=settings)}
    fm = sources["sender:flowmailer"]
    assert fm.name == "Flowmailer" and fm.messages == 1200 and fm.failing == 1200
    assert fm.spf_pass_unaligned == 1200 and fm.dkim_pass_unaligned == 1200
    assert dict(fm.envelope_domains) == {"bounce.esp-example.net": 1200}
    assert dict(fm.dkim_domains) == {"mailer.esp-example.net": 1200}
    assert sources["sender:microsoft365"].pct(sources["sender:microsoft365"].dmarc_pass) == 100.0
    spoof = sources["asn:64500"]
    assert not spoof.recognised and not spoof.considered_legit


def test_recommendations_in_plain_language(loaded, session, settings):
    recs = recommendations(session, "example.com", NOW, settings)
    [fm] = [r for r in recs if r.source_key == "sender:flowmailer"]
    assert fm.title == "Flowmailer sends ~8,400 mails/week on behalf of example.com; 100.0% fails DMARC"
    assert "mailer.esp-example.net instead of your own domain" in fm.text
    assert "bounce.esp-example.net" in fm.text
    assert any("DKIM" in a and "Flowmailer" in a for a in fm.actions)
    assert any("return-path" in a for a in fm.actions)
    # The 3-message spoofing source is below the threshold...
    assert not [r for r in recs if r.code == "source.unknown_failing"]
    # ...but is reported with a lower threshold.
    settings.significant_messages = 1
    recs = recommendations(session, "example.com", NOW, settings)
    [u] = [r for r in recs if r.code == "source.unknown_failing"]
    assert "Example Bulletproof Hosting" in u.title and "spoofing" in u.text


def test_missing_spf_include_recommendation(loaded, session, settings):
    # Microsoft 365 mail fails SPF when the include is missing from our record.
    xml = fixture_bytes("src", "microsoft.xml").replace(b"<result>pass</result>\n      </spf>", b"<result>fail</result>\n      </spf>")
    xml = xml.replace(b"a1b2c3d4", b"ffffffff").replace(b"<result>pass</result>\n      </dkim>", b"<result>fail</result>\n      </dkim>")
    from dmarc.storage import ingest_file

    ingest_file(session, xml, "ms-fail.xml", settings)
    assign_sources(session, loaded)
    check = session.scalars(select(m.DnsCheck)).one()
    check.result = {**check.result, "spf": {**check.result["spf"], "includes": []}}
    session.commit()
    recs = recommendations(session, "example.com", NOW, settings)
    [ms] = [r for r in recs if r.source_key == "sender:microsoft365"]
    assert any(a.startswith("Add include:spf.protection.outlook.com") for a in ms.actions)


def test_readiness(loaded, session, settings):
    r = readiness(session, "example.com", NOW, settings)
    assert r["status"] == "not_ready" and r["policy"] == "none"
    crit = {c["key"]: c["ok"] for c in r["criteria"]}
    assert crit == {"dmarc_record": True, "reports": True, "spf": True, "data": False, "pass_rate": False, "senders": False}
    assert r["next_step"] is None

    # Admin decides the Flowmailer traffic is not ours (e.g. an old account abused) -> abuse.
    session.add(m.SourceClassification(domain="example.com", source_key="sender:flowmailer", status="abuse"))
    session.commit()
    settings.min_report_days = 1
    r = readiness(session, "example.com", NOW, settings)
    assert r["status"] == "ready" and r["pass_rate"] == 100.0
    assert r["next_step"]["title"] == "example.com is ready for p=quarantine"
    assert "p=quarantine; pct=25; rua=mailto:dmarc@example.com" in r["next_step"]["actions"][0]


def test_multiple_dmarc_records_blocks_readiness(loaded, session, settings, fake_dns):
    fake_dns.add("_dmarc.example.com", "TXT", "v=DMARC1; p=reject")
    run_dns_checks(session, settings, fake_dns, datetime(2025, 11, 26, 13, tzinfo=UTC))
    session.commit()
    recs = recommendations(session, "example.com", datetime(2025, 11, 26, 14, tzinfo=UTC), settings)
    assert recs[0].code == "dmarc.multiple" and "2 DMARC records" in recs[0].title
    r = readiness(session, "example.com", NOW, settings)
    assert not next(c for c in r["criteria"] if c["key"] == "dmarc_record")["ok"]
