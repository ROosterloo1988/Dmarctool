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
def worker(engine, session, settings, mailbox_factory, clock):
    return Worker(engine, settings, mailbox_factory, now=clock)


def test_fetch_skipped_without_mailbox(worker, session):
    runs = worker.tick()
    fetch = next(r for r in runs if r.job == "fetch")
    assert fetch.status == "skipped" and "mailbox.address" in fetch.error


def test_schedule(worker, session, clock, fake_graph):
    set_value(session, "mailbox.address", "dmarc@example.com")
    session.commit()
    fake_graph.add_message(fixture_bytes("rua", "google.eml"))

    first = worker.tick()
    assert sorted(r.job for r in first) == ["fetch", "purge"]
    fetch = next(r for r in first if r.job == "fetch")
    assert fetch.status == "ok" and fetch.stats["processed"] == 1

    clock.t += timedelta(minutes=10)
    assert worker.tick() == []  # neither due yet
    clock.t += timedelta(minutes=5)
    assert [r.job for r in worker.tick()] == ["fetch"]  # 15 minutes passed

    clock.t = clock.t.replace(hour=1) + timedelta(days=1)
    assert [r.job for r in worker.tick()] == ["fetch"]  # purge waits until 03:00 UTC
    clock.t = clock.t.replace(hour=3, minute=30)
    assert sorted(r.job for r in worker.tick()) == ["fetch", "purge"]


def test_poll_interval_and_disable_from_settings(worker, session, clock):
    set_value(session, "mailbox.address", "dmarc@example.com")
    set_value(session, "mailbox.poll_minutes", 60)
    session.commit()
    worker.tick()
    clock.t += timedelta(minutes=30)
    assert worker.due_jobs() == []
    clock.t += timedelta(minutes=30)
    assert worker.due_jobs() == ["fetch"]
    set_value(session, "mailbox.enabled", False)
    session.commit()
    assert worker.due_jobs() == []


def test_queued_job_runs_immediately(worker, session, clock):
    set_value(session, "mailbox.address", "dmarc@example.com")
    session.commit()
    worker.tick()
    clock.t += timedelta(minutes=1)
    run = queue_job(session, "fetch", requested_by="admin@example.com")
    assert queue_job(session, "fetch").id == run.id  # no double queueing
    session.commit()
    [done] = worker.tick()
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
