"""Daily roll-ups for dashboards and trends (kept after detailed records are purged)."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from sqlalchemy import bindparam, delete, select, text, update
from sqlalchemy.orm import Session

from dmarc.db import models as m
from dmarc.enrich import source_names
from dmarc.senders import Catalog

ROLLUP_SQL = text("""
    INSERT INTO daily_stat (domain, day, source_key, source_name, messages, dmarc_pass, spf_aligned, dkim_aligned,
                            spf_pass, dkim_pass, disp_quarantine, disp_reject, forwarded)
    SELECT rep.domain,
           ((rep.date_begin + (rep.date_end - rep.date_begin) / 2) AT TIME ZONE 'UTC')::date AS day,
           coalesce(r.source_key, 'pending'),
           NULL,
           sum(r.count),
           coalesce(sum(r.count) FILTER (WHERE r.dmarc_pass), 0),
           coalesce(sum(r.count) FILTER (WHERE r.spf_aligned), 0),
           coalesce(sum(r.count) FILTER (WHERE r.dkim_aligned), 0),
           coalesce(sum(r.count) FILTER (WHERE EXISTS (SELECT 1 FROM auth_result a
                     WHERE a.record_id = r.id AND a.method = 'spf' AND a.result = 'pass')), 0),
           coalesce(sum(r.count) FILTER (WHERE EXISTS (SELECT 1 FROM auth_result a
                     WHERE a.record_id = r.id AND a.method = 'dkim' AND a.result = 'pass')), 0),
           coalesce(sum(r.count) FILTER (WHERE r.disposition = 'quarantine'), 0),
           coalesce(sum(r.count) FILTER (WHERE r.disposition = 'reject'), 0),
           coalesce(sum(r.count) FILTER (WHERE r.reasons @> '[{"type": "forwarded"}]'
                                           OR r.reasons @> '[{"type": "mailing_list"}]'), 0)
    FROM aggregate_record r
    JOIN aggregate_report rep ON rep.id = r.report_id
    WHERE ((rep.date_begin + (rep.date_end - rep.date_begin) / 2) AT TIME ZONE 'UTC')::date >= :since
    GROUP BY 1, 2, 3
""")


def rebuild_daily(session: Session, since: date, catalog: Catalog) -> int:
    """Recompute daily_stat for all days >= ``since`` from the detailed records."""
    session.execute(delete(m.DailyStat).where(m.DailyStat.day >= since))
    session.execute(ROLLUP_SQL, {"since": since})
    keys = set(session.scalars(select(m.DailyStat.source_key).where(m.DailyStat.day >= since).distinct()))
    names = source_names(session, keys, catalog)
    if names:
        tbl = m.DailyStat.__table__
        session.connection().execute(
            update(tbl).where(tbl.c.source_key == bindparam("k"), tbl.c.day >= since).values(source_name=bindparam("n")),
            [{"k": k, "n": (n or "")[:255]} for k, n in names.items()],
        )
    session.flush()
    return len(keys)


def rollup_since(session: Session, created_after: datetime | None, window_days: int = 45,
                 now: datetime | None = None) -> date:
    """First day that needs recomputing: the rolling window, or older days touched by late/backfilled reports."""
    now = now or datetime.now(UTC)
    since = (now - timedelta(days=window_days)).date()
    if created_after is not None:
        oldest = session.scalar(
            select(m.AggregateReport.date_begin).where(m.AggregateReport.created_at > created_after)
            .order_by(m.AggregateReport.date_begin).limit(1)
        )
        if oldest is not None and oldest.date() < since:
            since = oldest.date()
    else:
        oldest = session.scalar(select(m.AggregateReport.date_begin).order_by(m.AggregateReport.date_begin).limit(1))
        if oldest is not None:
            since = min(since, oldest.date())
    return since
