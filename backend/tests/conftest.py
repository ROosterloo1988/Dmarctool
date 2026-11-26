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
            "TRUNCATE auth_result, aggregate_record, aggregate_report, forensic_report, inbound_message, domain "
            "RESTART IDENTITY CASCADE"
        ))
    with Session(engine) as s:
        yield s
        s.rollback()
