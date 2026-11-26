from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import select

from dmarc.alerts import render, run_alerts
from dmarc.appsettings import SettingError, notify_config, set_value
from dmarc.db import models as m
from dmarc.dnscheck.run import run_dns_checks
from dmarc.enrich import assign_sources, enrich_ips
from dmarc.geoip import GeoIp
from dmarc.senders import load_catalog
from dmarc.stats import rebuild_daily
from dmarc.storage import ingest_email
from tests.conftest import fixture_bytes

T0 = datetime(2025, 11, 26, 5, 0, tzinfo=UTC)  # before the default digest hour (06 UTC)


@pytest.fixture
def setup(session, settings, fake_dns, geoip_files):
    for name in ("google.eml", "microsoft.eml", "yahoo.eml"):
        ingest_email(session, fixture_bytes("rua", name), settings=settings)
    session.add(m.Domain(name="example.com"))
    session.commit()
    settings.geoip_dir = str(geoip_files)
    catalog = load_catalog()
    enrich_ips(session, fake_dns, GeoIp.from_settings(settings), catalog, settings, T0)
    assign_sources(session, catalog)
    rebuild_daily(session, date(2025, 1, 1), catalog)
    run_dns_checks(session, settings, fake_dns, T0)
    set_value(session, "mailbox.address", "dmarc@example.com")
    set_value(session, "notify.recipients", "it@example.com; security@example.com")
    session.commit()
    return fake_dns


def events(session, **kw):
    q = select(m.AlertEvent).order_by(m.AlertEvent.id)
    for k, v in kw.items():
        q = q.where(getattr(m.AlertEvent, k) == v)
    return session.scalars(q).all()


def test_recipient_setting(session, settings):
    assert set_value(session, "notify.recipients", "A@x.com, b@y.org\nA@x.com") == ["a@x.com", "b@y.org"]
    assert set_value(session, "notify.recipients", ["c@z.net"]) == ["c@z.net"]
    assert set_value(session, "notify.recipients", "") == []
    with pytest.raises(SettingError):
        set_value(session, "notify.recipients", "not-an-address")
    with pytest.raises(SettingError):
        set_value(session, "notify.pass_drop_points", 0)
    assert notify_config(session, settings).digest_hour_utc == 6


def test_dns_warnings_go_to_digest_once(setup, session, settings, mailbox_factory, fake_graph):
    r = run_alerts(session, mailbox_factory, settings, T0)
    assert r["immediate_sent"] == 0 and r["digest_sent"] == 0  # 05:00, digest at 06:00
    warn = events(session, kind="dns")
    assert {e.key for e in warn} == {"dns:dkim.selector_missing:selector1", "dns:dkim.selector_missing:selector2"}
    assert all(e.severity == "warning" and not e.immediate for e in warn)

    r = run_alerts(session, mailbox_factory, settings, T0 + timedelta(hours=1, minutes=5))
    assert r["created"] == 0 and r["digest_sent"] == 2
    [mail] = fake_graph.sent
    msg = mail["message"]
    assert msg["subject"] == "DMARC daily summary: 2 item(s)"
    assert [x["emailAddress"]["address"] for x in msg["toRecipients"]] == ["it@example.com", "security@example.com"]
    assert "selector1._domainkey.example.com" in msg["body"]["content"]
    assert "https://dmarcportal.tenazenergy.com/dns" in msg["body"]["content"]

    # Same day, later: no second digest; next day nothing new -> no mail either.
    assert run_alerts(session, mailbox_factory, settings, T0 + timedelta(hours=5))["digest_sent"] == 0
    assert run_alerts(session, mailbox_factory, settings, T0 + timedelta(days=1, hours=2))["digest_sent"] == 0
    assert len(fake_graph.sent) == 1


def test_dns_error_is_sent_immediately_and_resolution_reported(setup, session, settings, mailbox_factory, fake_graph):
    run_alerts(session, mailbox_factory, settings, T0)
    setup.add("_dmarc.example.com", "TXT", "v=DMARC1; p=reject")  # second DMARC record
    run_dns_checks(session, settings, setup, T0 + timedelta(minutes=30))
    r = run_alerts(session, mailbox_factory, settings, T0 + timedelta(minutes=31))
    assert r["immediate_sent"] == 1
    [mail] = fake_graph.sent
    assert mail["message"]["subject"].startswith("DNS problem for example.com: There are 2 DMARC records")
    assert "Remove all but one" in mail["message"]["body"]["content"]

    # Still broken an hour later: not sent again.
    run_dns_checks(session, settings, setup, T0 + timedelta(minutes=50))
    assert run_alerts(session, mailbox_factory, settings, T0 + timedelta(minutes=51))["immediate_sent"] == 0

    # Fixed: reported as resolved in the digest.
    setup.records[("_dmarc.example.com", "TXT")] = ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"]
    run_dns_checks(session, settings, setup, T0 + timedelta(hours=1, minutes=10))
    run_alerts(session, mailbox_factory, settings, T0 + timedelta(hours=1, minutes=11))
    digest = fake_graph.sent[-1]["message"]
    assert digest["subject"].startswith("DMARC daily summary")
    assert "Resolved for example.com: dmarc.multiple" in digest["body"]["content"]


def test_new_unknown_sender(setup, session, settings, mailbox_factory):
    run_alerts(session, mailbox_factory, settings, T0)
    assert events(session, kind="new_source") == []  # 3 and 5 messages: below the threshold of 50
    set_value(session, "notify.new_source_min_messages", 3)
    session.commit()
    run_alerts(session, mailbox_factory, settings, T0 + timedelta(minutes=15))
    new = {e.key: e for e in events(session, kind="new_source")}
    assert set(new) == {"source:asn:64500", "source:asn:64502"}  # recognised senders are never reported
    assert new["source:asn:64500"].title == "New unknown sender for example.com: Example Bulletproof Hosting (AS64500)"
    assert "0.0% passed DMARC" in new["source:asn:64500"].text
    run_alerts(session, mailbox_factory, settings, T0 + timedelta(minutes=30))
    assert len(events(session, kind="new_source")) == 2  # reported once only


def test_classified_sources_are_not_reported(setup, session, settings, mailbox_factory):
    set_value(session, "notify.new_source_min_messages", 1)
    session.add(m.SourceClassification(domain="example.com", source_key="asn:64500", status="abuse"))
    session.commit()
    run_alerts(session, mailbox_factory, settings, T0)
    assert {e.key for e in events(session, kind="new_source")} == {"source:asn:64502"}


def test_pass_rate_drop(session, settings, mailbox_factory):
    session.add(m.Domain(name="example.com"))
    for i in range(14):
        day = (T0 - timedelta(days=i)).date()
        passed = 80 if i < 7 else 98  # last 7 days 80%, the 7 days before 98%
        session.add(m.DailyStat(domain="example.com", day=day, source_key="sender:microsoft365", source_name="M365",
                                messages=100, dmarc_pass=passed, spf_aligned=0, dkim_aligned=0, spf_pass=0, dkim_pass=0,
                                disp_quarantine=0, disp_reject=0, forwarded=0))
    session.commit()
    run_alerts(session, mailbox_factory, settings, T0)
    [e] = events(session, kind="pass_drop")
    assert e.title == "DMARC pass rate for example.com dropped from 98.0% to 80.0%"
    run_alerts(session, mailbox_factory, settings, T0 + timedelta(days=2))
    assert len(events(session, kind="pass_drop")) == 1  # at most weekly


def test_disabled_or_no_recipients(setup, session, settings, mailbox_factory, fake_graph):
    set_value(session, "notify.enabled", False)
    session.commit()
    r = run_alerts(session, mailbox_factory, settings, T0 + timedelta(hours=2))
    assert r["skipped"] and fake_graph.sent == []
    assert events(session, kind="dns")  # still detected, so nothing is lost when switched on


def test_send_failure_is_retried(setup, session, settings, mailbox_factory, fake_graph):
    fake_graph.fail_send = True
    r = run_alerts(session, mailbox_factory, settings, T0 + timedelta(hours=2))
    assert r["digest_sent"] == 0 and "errors" in r
    assert all(e.send_error and e.sent_at is None for e in events(session, kind="dns"))
    fake_graph.fail_send = False
    r = run_alerts(session, mailbox_factory, settings, T0 + timedelta(hours=2, minutes=15))
    assert r["digest_sent"] == 2 and len(fake_graph.sent) == 1


def test_render_escapes_html():
    ev = m.AlertEvent(domain="example.com", kind="new_source", severity="warning", key="k",
                      title='New sender <script>alert(1)</script>', text="a & b", link='https://x/"y',
                      immediate=False, created_at=T0)
    subject, body, text = render([ev], True, "https://portal")
    assert "<script>" not in body and "&lt;script&gt;" in body and "a &amp; b" in body and "&quot;y" in body
    assert subject == "DMARC daily summary: 1 item(s)" and "<script>" in text


def test_worker_runs_alerts_job(setup, engine, settings, mailbox_factory, fake_dns):
    from dmarc.worker import Worker

    settings.geoip_auto_download = False
    w = Worker(engine, settings, mailbox_factory, now=lambda: T0, resolver=fake_dns)
    run = w.run_job("alerts")
    assert run.status == "ok" and run.stats["created"] == 2
