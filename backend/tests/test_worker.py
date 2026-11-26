from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from dmarc.appsettings import set_value
from dmarc.db.models import JobRun
from dmarc.worker import Worker, queue_job
from tests.conftest import fixture_bytes


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def clock():
    return Clock(datetime(2026, 1, 10, 12, 0, tzinfo=UTC))


@pytest.fixture
def worker(engine, session, settings, mailbox_factory, clock, fake_dns, geoip_files):
    settings.geoip_dir = str(geoip_files)
    settings.geoip_auto_download = False
    return Worker(engine, settings, mailbox_factory, now=clock, resolver=fake_dns)


def jobs(runs, only=("fetch", "purge")):
    return sorted(r.job for r in runs if r.job in only)


def test_fetch_skipped_without_mailbox(worker, session):
    runs = worker.tick()
    fetch = next(r for r in runs if r.job == "fetch")
    assert fetch.status == "skipped" and "mailbox.address" in fetch.error


def test_schedule(worker, session, clock, fake_graph):
    set_value(session, "mailbox.address", "dmarc@example.com")
    session.commit()
    fake_graph.add_message(fixture_bytes("rua", "google.eml"))

    first = worker.tick()
    assert [r.job for r in first] == ["fetch", "enrich", "dnscheck", "purge"]
    fetch = next(r for r in first if r.job == "fetch")
    assert fetch.status == "ok" and fetch.stats["processed"] == 1

    clock.t += timedelta(minutes=10)
    assert worker.tick() == []  # nothing due yet
    clock.t += timedelta(minutes=5)
    assert [r.job for r in worker.tick()] == ["fetch", "enrich"]  # 15 minutes passed

    clock.t = clock.t.replace(hour=1) + timedelta(days=1)
    assert jobs(worker.tick()) == ["fetch"]  # purge waits until 03:00 UTC
    clock.t = clock.t.replace(hour=3, minute=30)
    assert jobs(worker.tick()) == ["fetch", "purge"]


def test_poll_interval_and_disable_from_settings(worker, session, clock):
    set_value(session, "mailbox.address", "dmarc@example.com")
    set_value(session, "mailbox.poll_minutes", 60)
    session.commit()
    worker.tick()
    clock.t += timedelta(minutes=30)
    assert "fetch" not in worker.due_jobs()
    clock.t += timedelta(minutes=30)
    assert "fetch" in worker.due_jobs()
    set_value(session, "mailbox.enabled", False)
    session.commit()
    assert "fetch" not in worker.due_jobs()


def test_queued_job_runs_immediately(worker, session, clock):
    set_value(session, "mailbox.address", "dmarc@example.com")
    session.commit()
    worker.tick()
    clock.t += timedelta(minutes=1)
    run = queue_job(session, "fetch", requested_by="admin@example.com")
    assert queue_job(session, "fetch").id == run.id  # no double queueing
    session.commit()
    [done] = worker.tick()  # only the queued fetch; enrich/dnscheck ran a minute ago
    assert done.id == run.id and done.status == "ok" and done.requested_by == "admin@example.com"


def test_job_error_is_recorded(worker, session, fake_graph):
    set_value(session, "mailbox.address", "dmarc@example.com")
    session.commit()
    fake_graph.deny = True
    fetch = next(r for r in worker.tick() if r.job == "fetch")
    assert fetch.status == "error" and "403" in fetch.error


def test_recover_stale(worker, session):
    session.add(JobRun(job="fetch", status="running", started_at=datetime(2026, 1, 1, tzinfo=UTC)))
    session.commit()
    worker.recover_stale()
    session.expire_all()
    assert session.scalars(select(JobRun)).one().status == "error"


def test_enrich_and_dnscheck_jobs(worker, session, settings):
    from dmarc.db.models import DailyStat, DnsCheck, Domain
    from dmarc.storage import ingest_email

    ingest_email(session, fixture_bytes("rua", "google.eml"), settings=settings)
    session.add(Domain(name="example.com"))
    session.commit()
    enrich = worker.run_job("enrich")
    assert enrich.status == "ok", enrich.error
    assert enrich.stats["ips_enriched"] == 3 and enrich.stats["records_assigned"] == 3
    assert enrich.stats["geoip_available"] is True and enrich.stats["rollup_since"] == "2025-11-24"
    assert session.query(DailyStat).count() == 3
    dns = worker.run_job("dnscheck")
    # Report is older than 30 days at the worker clock, so no selectors to check yet.
    assert dns.status == "ok" and dns.stats == {"example.com": {"error": 0, "warning": 0}}
    assert session.query(DnsCheck).count() == 1


def test_geoip_job(engine, session, settings, mailbox_factory, clock, tmp_path):
    settings.geoip_dir = str(tmp_path)
    calls = []
    w = Worker(engine, settings, mailbox_factory, now=clock, geoip_downloader=lambda s: calls.append(s) or {"asn": "2026-01"})
    assert "geoip" in w.due_jobs()
    run = w.run_job("geoip")
    assert run.status == "ok" and run.stats == {"asn": "2026-01"} and len(calls) == 1
    assert "geoip" not in w.due_jobs()  # checked again tomorrow
