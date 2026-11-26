from __future__ import annotations

import os
from pathlib import Path

import pytest

from dmarc.config import Settings

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_bytes(*parts: str) -> bytes:
    return FIXTURES.joinpath(*parts).read_bytes()


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None)


@pytest.fixture(scope="session")
def engine():
    url = os.environ.get("DMARC_TEST_DATABASE_URL")
    if not url:
        pytest.skip("DMARC_TEST_DATABASE_URL not set; skipping database tests")
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, text

    eng = create_engine(url)
    with eng.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public"))
    root = Path(__file__).resolve().parent.parent
    cfg = Config(str(root / "alembic.ini"))
    cfg.attributes["database_url"] = url
    command.upgrade(cfg, "head")
    yield eng
    eng.dispose()


@pytest.fixture
def session(engine):
    from sqlalchemy import text
    from sqlalchemy.orm import Session

    with engine.begin() as conn:
        conn.execute(text(
            "TRUNCATE auth_result, aggregate_record, aggregate_report, forensic_report, inbound_message, domain, "
            "app_setting, job_run "
            "RESTART IDENTITY CASCADE"
        ))
    with Session(engine) as s:
        yield s
        s.rollback()


@pytest.fixture
def sessions(engine, session):
    """A sessionmaker on the (freshly truncated) test database, for code that opens its own sessions."""
    from sqlalchemy.orm import sessionmaker

    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture
def fake_graph():
    from tests.fake_graph import FakeGraph

    return FakeGraph()


@pytest.fixture
def mailbox_factory(fake_graph, settings):
    import httpx

    from dmarc.graph import GraphMailbox

    def factory(address):
        return GraphMailbox(address, lambda: "test-token", settings,
                            http=httpx.Client(transport=fake_graph.transport()), sleep=lambda s: None)

    return factory
