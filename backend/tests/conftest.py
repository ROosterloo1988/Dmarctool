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
            "app_setting, job_run, ip_info, dns_check, daily_stat, source_classification, app_user, audit_log "
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


GEO_NETWORKS = {
    "40.107.0.0/16": (8075, "Microsoft Corporation", "IE"),
    "2a01:111::/32": (8075, "Microsoft Corporation", "IE"),
    "198.51.100.0/24": (64501, "Example ESP B.V.", "NL"),
    "203.0.113.0/24": (64500, "Example Bulletproof Hosting", "RU"),
    "209.85.128.0/17": (15169, "Google LLC", "US"),
    "192.0.2.0/24": (64502, "Example ISP", "NL"),
}


@pytest.fixture(scope="session")
def geoip_files(tmp_path_factory):
    from mmdb_writer import MMDBWriter
    from netaddr import IPSet

    d = tmp_path_factory.mktemp("geoip")
    asn = MMDBWriter(ip_version=6, ipv4_compatible=True, database_type="DBIP-ASN-Lite (compat=GeoLite2-ASN)")
    country = MMDBWriter(ip_version=6, ipv4_compatible=True, database_type="DBIP-Country-Lite")
    for net, (num, org, cc) in GEO_NETWORKS.items():
        asn.insert_network(IPSet([net]), {"autonomous_system_number": num, "autonomous_system_organization": org})
        country.insert_network(IPSet([net]), {"country": {"iso_code": cc}})
    asn.to_db_file(str(d / "dbip-asn-lite.mmdb"))
    country.to_db_file(str(d / "dbip-country-lite.mmdb"))
    return d


@pytest.fixture
def fake_dns():
    return make_fake_dns()


def make_fake_dns():
    """DNS for the example.com test domain and the source IPs used in the fixtures."""
    from dmarc.dnscheck.resolver import FakeResolver

    r = FakeResolver()
    r.add("_dmarc.example.com", "TXT", "v=DMARC1; p=none; rua=mailto:dmarc@example.com")
    r.add("example.com", "TXT", "v=spf1 include:spf.protection.outlook.com -all")
    r.add("spf.protection.outlook.com", "TXT", "v=spf1 ip4:40.107.0.0/16 ip6:2a01:111:f400::/48 -all")
    # Forward-confirmed PTRs
    for ip, name in {"40.107.22.105": "mail-db8eur05on2105.outbound.protection.outlook.com",
                     "198.51.100.23": "o1.mailer.flowmailer.net",
                     "209.85.220.41": "mail-sor-f41.google.com"}.items():
        r.add(__import__("dns.reversename").reversename.from_address(ip).to_text(), "PTR", name)
        r.add(name, "A", ip)
    r.add(__import__("dns.reversename").reversename.from_address("2a01:111:f403:c201::1").to_text(), "PTR",
          "mail-he1eur02on0001.outbound.protection.outlook.com")
    r.add("mail-he1eur02on0001.outbound.protection.outlook.com", "AAAA", "2a01:111:f403:c201::1")
    # A spoofer pretending to be Flowmailer in reverse DNS, but not forward-confirmed
    r.add(__import__("dns.reversename").reversename.from_address("203.0.113.77").to_text(), "PTR", "fake.flowmailer.net")
    return r
