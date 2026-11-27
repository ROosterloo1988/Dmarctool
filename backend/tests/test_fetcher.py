import pytest
from sqlalchemy import func, select

from dmarc.appsettings import set_value
from dmarc.db import models as m
from dmarc.fetcher import run_fetch
from dmarc.graph import GraphError, GraphNotConfigured
from tests.conftest import fixture_bytes


@pytest.fixture
def configured(session):
    set_value(session, "mailbox.address", "dmarc@example.com")
    session.commit()


def count(session, model):
    return session.scalar(select(func.count()).select_from(model))


def load_inbox(fake):
    return {
        "google": fake.add_message(fixture_bytes("rua", "google.eml"), "google"),
        "ms": fake.add_message(fixture_bytes("rua", "microsoft.eml"), "microsoft"),
        "ruf": fake.add_message(fixture_bytes("ruf", "arf_full.eml"), "ruf"),
        "mixed": fake.add_message(fixture_bytes("broken", "mixed.eml"), "mixed"),
        "lunch": fake.add_message(fixture_bytes("broken", "no_report.eml"), "Lunch?"),
        "google-again": fake.add_message(fixture_bytes("rua", "google.eml"), "google resend"),
    }


def test_full_run(configured, sessions, session, fake_graph, mailbox_factory, settings):
    load_inbox(fake_graph)
    stats = run_fetch(sessions, mailbox_factory, settings)

    assert stats.as_dict() | {} == {
        "seen": 6, "processed": 3, "duplicate": 1, "partial": 1, "failed": 1, "reports_new": 4,
        "moved": 6, "move_retried": 0, "download_errors": 0, "move_errors": 0,
    }
    assert fake_graph.in_folder("Inbox") == []
    assert sorted(x.subject for x in fake_graph.in_folder("Verwerkt")) == ["google", "google resend", "microsoft", "ruf"]
    assert sorted(x.subject for x in fake_graph.in_folder("Fout")) == ["Lunch?", "mixed"]

    assert count(session, m.AggregateReport) == 3  # google, microsoft, good half of mixed
    assert count(session, m.ForensicReport) == 1
    rows = session.scalars(select(m.InboundMessage).order_by(m.InboundMessage.id)).all()
    assert [r.moved_to for r in rows] == ["Verwerkt", "Verwerkt", "Verwerkt", "Fout", "Fout", "Verwerkt"]
    assert all(r.source == "graph" and r.received_at is not None for r in rows)

    # Second run: inbox empty, nothing changes.
    again = run_fetch(sessions, mailbox_factory, settings)
    assert again.seen == 0 and count(session, m.InboundMessage) == 6


def test_report_moved_back_to_inbox_is_not_duplicated(configured, sessions, session, fake_graph, mailbox_factory, settings):
    fake_graph.add_message(fixture_bytes("rua", "google.eml"))
    run_fetch(sessions, mailbox_factory, settings)
    [msg] = fake_graph.in_folder("Verwerkt")
    msg.folder = "inbox-id"  # someone drags it back
    stats = run_fetch(sessions, mailbox_factory, settings)
    assert stats.duplicate == 1 and count(session, m.AggregateReport) == 1
    assert len(fake_graph.in_folder("Verwerkt")) == 1


def test_download_error_leaves_mail_in_inbox(configured, sessions, session, fake_graph, mailbox_factory, settings):
    ids = load_inbox(fake_graph)
    fake_graph.fail_download.add(ids["ms"])
    stats = run_fetch(sessions, mailbox_factory, settings)
    assert stats.download_errors == 1 and stats.seen == 6
    assert [x.subject for x in fake_graph.in_folder("Inbox")] == ["microsoft"]

    fake_graph.fail_download.clear()
    stats = run_fetch(sessions, mailbox_factory, settings)
    assert stats.processed == 1 and fake_graph.in_folder("Inbox") == []


def test_failed_move_is_retried_without_reprocessing(configured, sessions, session, fake_graph, mailbox_factory, settings):
    mid = fake_graph.add_message(fixture_bytes("rua", "google.eml"))
    fake_graph.fail_move.add(mid)
    stats = run_fetch(sessions, mailbox_factory, settings)
    assert stats.processed == 1 and stats.move_errors == 1
    row = session.scalars(select(m.InboundMessage)).one()
    assert row.moved_to is None and "move failed" in row.move_error

    fake_graph.fail_move.clear()
    stats = run_fetch(sessions, mailbox_factory, settings)
    assert stats.move_retried == 1 and stats.moved == 1 and stats.processed == stats.duplicate == 0
    session.expire_all()
    row = session.scalars(select(m.InboundMessage)).one()
    assert row.status == "processed" and row.moved_to == "Verwerkt" and row.move_error is None


def test_too_large_message_goes_to_failed(configured, sessions, session, fake_graph, mailbox_factory, settings):
    fake_graph.add_message(fixture_bytes("rua", "google.eml"), "huge")
    settings.max_message_bytes = 500
    stats = run_fetch(sessions, mailbox_factory, settings)
    assert stats.failed == 1 and [x.subject for x in fake_graph.in_folder("Fout")] == ["huge"]
    row = session.scalars(select(m.InboundMessage)).one()
    assert row.subject == "huge" and "exceeds limit" in row.errors[0]


def test_custom_folders_from_settings(configured, sessions, session, fake_graph, mailbox_factory, settings):
    set_value(session, "mailbox.source_folder", "Inbox/DMARC")
    set_value(session, "mailbox.processed_folder", "Inbox/DMARC/Done")
    session.commit()
    dmarc_id = mailbox_factory("dmarc@example.com").resolve_folder("Inbox/DMARC", create=True)
    fake_graph.add_message(fixture_bytes("rua", "yahoo.eml"), "yahoo", folder=dmarc_id)
    fake_graph.add_message(fixture_bytes("rua", "google.eml"), "stays in inbox")
    stats = run_fetch(sessions, mailbox_factory, settings)
    assert stats.processed == 1
    assert [x.subject for x in fake_graph.in_folder("Done")] == ["yahoo"]
    assert [x.subject for x in fake_graph.in_folder("Inbox")] == ["stays in inbox"]


def test_batch_size(configured, sessions, session, fake_graph, mailbox_factory, settings):
    set_value(session, "mailbox.batch_size", 2)
    session.commit()
    load_inbox(fake_graph)
    assert run_fetch(sessions, mailbox_factory, settings).seen == 2
    assert len(fake_graph.in_folder("Inbox")) == 4


def test_not_configured(sessions, fake_graph, mailbox_factory, settings):
    with pytest.raises(GraphNotConfigured):
        run_fetch(sessions, mailbox_factory, settings)


def test_same_folder_twice_is_rejected(configured, sessions, session, mailbox_factory, settings):
    set_value(session, "mailbox.processed_folder", "inbox")
    session.commit()
    with pytest.raises(GraphError, match="different"):
        run_fetch(sessions, mailbox_factory, settings)
