"""Background worker: runs scheduled jobs and jobs queued from the UI.

Jobs:
- ``fetch``: read the mailbox every ``mailbox.poll_minutes`` (setting, default 15).
- ``enrich``: reverse DNS / ASN for new source IPs, assign sources, rebuild daily stats.
- ``dnscheck``: check DMARC/SPF/DKIM of our domains every ``DMARC_DNS_CHECK_MINUTES``.
- ``geoip``: refresh the DB-IP Lite databases when older than 30 days (daily check).
- ``purge``: once a day after ``DMARC_PURGE_HOUR_UTC`` apply retention periods.

Only one worker is active at a time (PostgreSQL advisory lock); a second instance
waits as a hot standby. Every run is recorded in ``job_run`` for the UI.
"""

from __future__ import annotations

import logging
import signal
import threading
import traceback
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import Engine, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from dmarc.appsettings import mailbox_config
from dmarc.config import Settings, get_settings
from dmarc.db.models import JobRun
from dmarc.fetcher import MailboxFactory, run_fetch
from dmarc.graph import GraphMailbox, GraphNotConfigured, msal_token_provider
from dmarc.dnscheck.resolver import DnsPythonResolver, Resolver
from dmarc.storage import purge_expired

log = logging.getLogger(__name__)

WORKER_LOCK_ID = 0x444D41524331  # "DMARC1"
JOBS = ("fetch", "enrich", "dnscheck", "geoip", "purge")


def default_mailbox_factory(settings: Settings) -> MailboxFactory:
    token = None

    def factory(address: str) -> GraphMailbox:
        nonlocal token
        if token is None:
            token = msal_token_provider(settings)
        return GraphMailbox(address, token, settings)

    return factory


class Worker:
    def __init__(
        self,
        engine: Engine,
        settings: Settings | None = None,
        mailbox_factory: MailboxFactory | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        resolver: Resolver | None = None,
        geoip_downloader: Callable[[Settings], dict] | None = None,
    ):
        self.engine = engine
        self.settings = settings or get_settings()
        self.sessions = sessionmaker(bind=engine, expire_on_commit=False)
        self.mailbox_factory = mailbox_factory or default_mailbox_factory(self.settings)
        self.now = now
        self.resolver = resolver
        self.geoip_downloader = geoip_downloader
        self.stop_event = threading.Event()

    def _resolver(self) -> Resolver:
        if self.resolver is None:
            return DnsPythonResolver(self.settings.dns_nameservers or None, self.settings.dns_timeout_seconds)
        return self.resolver

    # -- scheduling ---------------------------------------------------------------------

    def _last_run(self, session: Session, job: str) -> JobRun | None:
        return session.scalars(
            select(JobRun)
            .where(JobRun.job == job, JobRun.status.in_(["ok", "error", "running", "skipped"]))
            .order_by(JobRun.started_at.desc().nulls_last())
            .limit(1)
        ).first()

    def due_jobs(self) -> list[str]:
        now = self.now()
        due = []
        with self.sessions() as session:
            cfg = mailbox_config(session, self.settings)

            def older_than(job: str, minutes: float) -> bool:
                last = self._last_run(session, job)
                return last is None or last.started_at <= now - timedelta(minutes=minutes)

            if cfg.enabled and older_than("fetch", cfg.poll_minutes):
                due.append("fetch")
            if older_than("enrich", self.settings.enrich_minutes):
                due.append("enrich")
            if older_than("dnscheck", self.settings.dns_check_minutes):
                due.append("dnscheck")
            if self.settings.geoip_auto_download and older_than("geoip", 24 * 60):
                due.append("geoip")
            last = self._last_run(session, "purge")
            if now.hour >= self.settings.purge_hour_utc and (last is None or last.started_at.date() < now.date()):
                due.append("purge")
        # Run geoip before enrich so a fresh install gets ASN data on the first pass.
        return sorted(due, key=lambda j: JOBS.index(j) if j != "geoip" else 0.5)

    def claim_queued(self) -> list[JobRun]:
        with self.sessions() as session:
            rows = session.scalars(
                select(JobRun).where(JobRun.status == "queued").order_by(JobRun.created_at)
                .with_for_update(skip_locked=True)
            ).all()
            for r in rows:
                r.status = "running"
                r.started_at = self.now()
            session.commit()
            return list(rows)

    # -- execution ----------------------------------------------------------------------

    def _execute(self, job: str) -> dict:
        if job == "fetch":
            return run_fetch(self.sessions, self.mailbox_factory, self.settings).as_dict()
        with self.sessions() as session:
            if job == "purge":
                result = purge_expired(session, self.settings, self.now())
            elif job == "enrich":
                result = self._enrich(session)
            elif job == "dnscheck":
                from dmarc.dnscheck.run import run_dns_checks

                result = run_dns_checks(session, self.settings, self._resolver(), self.now())
            elif job == "geoip":
                from dmarc.geoip import download_dbip, needs_update

                if not needs_update(self.settings, self.now()):
                    return {"updated": False}
                result = (self.geoip_downloader or download_dbip)(self.settings)
            else:
                raise ValueError(f"unknown job {job!r}")
            session.commit()
            return result

    def _enrich(self, session: Session) -> dict:
        from dmarc.enrich import assign_sources, enrich_ips
        from dmarc.geoip import GeoIp
        from dmarc.senders import load_catalog
        from dmarc.stats import rebuild_daily, rollup_since

        catalog = load_catalog()
        last_ok = session.scalars(
            select(JobRun.started_at).where(JobRun.job == "enrich", JobRun.status == "ok")
            .order_by(JobRun.started_at.desc()).limit(1)).first()
        geo = GeoIp.from_settings(self.settings)
        try:
            ips = enrich_ips(session, self._resolver(), geo, catalog, self.settings, self.now())
        finally:
            geo.close()
        session.commit()
        assigned = assign_sources(session, catalog)
        session.commit()
        since = rollup_since(session, last_ok, now=self.now())
        sources = rebuild_daily(session, since, catalog)
        return {"ips_enriched": ips, "records_assigned": assigned, "rollup_since": since.isoformat(),
                "rollup_sources": sources, "geoip_available": geo.available}

    def run_job(self, job: str, run: JobRun | None = None) -> JobRun:
        with self.sessions() as session:
            if run is None:
                run = JobRun(job=job, status="running", started_at=self.now())
                session.add(run)
            else:
                run = session.merge(run)
            session.commit()
            run_id = run.id

        status, stats, error = "ok", {}, None
        try:
            stats = self._execute(job)
        except GraphNotConfigured as exc:
            status, error = "skipped", str(exc)
            log.warning("job %s skipped: %s", job, exc)
        except Exception as exc:
            status, error = "error", f"{type(exc).__name__}: {exc}"
            log.error("job %s failed: %s\n%s", job, exc, traceback.format_exc())

        with self.sessions() as session:
            run = session.get(JobRun, run_id)
            run.status, run.stats, run.error, run.finished_at = status, stats, error, self.now()
            session.commit()
            return run

    def tick(self) -> list[JobRun]:
        done = []
        for run in self.claim_queued():
            done.append(self.run_job(run.job, run))
        for job in self.due_jobs():
            done.append(self.run_job(job))
        return done

    def recover_stale(self) -> None:
        """Runs left 'running' by a crashed worker are marked as errors."""
        with self.sessions() as session:
            session.execute(
                update(JobRun).where(JobRun.status == "running")
                .values(status="error", error="worker stopped during run", finished_at=self.now())
            )
            session.commit()

    def serve(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: self.stop_event.set())

        with self.engine.connect() as lock_conn:
            while not self.stop_event.is_set():
                if lock_conn.execute(text("SELECT pg_try_advisory_lock(:id)"), {"id": WORKER_LOCK_ID}).scalar():
                    break
                log.info("another worker holds the lock; standing by")
                self.stop_event.wait(30)
            if self.stop_event.is_set():
                return
            log.info("worker active (tick every %ss)", self.settings.worker_tick_seconds)
            self.recover_stale()
            while not self.stop_event.is_set():
                try:
                    self.tick()
                except Exception:
                    log.exception("worker tick failed")
                self.stop_event.wait(self.settings.worker_tick_seconds)
        log.info("worker stopped")


def queue_job(session: Session, job: str, requested_by: str | None = None) -> JobRun:
    """Ask the worker to run a job as soon as possible (used by the CLI and later the UI)."""
    if job not in JOBS:
        raise ValueError(f"unknown job {job!r}")
    pending = session.scalars(select(JobRun).where(JobRun.job == job, JobRun.status.in_(["queued", "running"]))).first()
    if pending:
        return pending
    run = JobRun(job=job, status="queued", requested_by=requested_by)
    session.add(run)
    session.flush()
    return run
