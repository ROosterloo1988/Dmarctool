import pytest
from pydantic import SecretStr
from sqlalchemy import select

from dmarc import graph as graph_mod
from dmarc.appsettings import SettingError, set_value
from dmarc.db.models import SecretSetting
from dmarc.graph import GraphNotConfigured, graph_credentials, msal_token_provider
from dmarc.secrets_store import SecretStoreError, delete_secret, get_secret, secret_status, set_secret

SECRET = "abc~DEF.ghi_123-super-secret"
TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "66666666-7777-8888-9999-000000000000"


@pytest.fixture
def s(settings):
    settings.secret_key = SecretStr("k" * 40)
    return settings


def test_secret_is_encrypted_and_write_only(session, s):
    set_secret(session, "graph.client_secret", f"  {SECRET} ", "admin", s)
    row = session.scalars(select(SecretSetting)).one()
    assert SECRET.encode() not in row.ciphertext
    assert get_secret(session, "graph.client_secret", s) == SECRET
    st = secret_status(session, "graph.client_secret", s)
    assert st["stored"] and st["readable"] and st["updated_by"] == "admin"
    assert SECRET not in repr(st)
    assert delete_secret(session, "graph.client_secret") and not secret_status(session, "graph.client_secret", s)["stored"]


def test_changed_secret_key_makes_secret_unreadable(session, s):
    set_secret(session, "graph.client_secret", SECRET, "admin", s)
    s.secret_key = SecretStr("z" * 40)
    assert get_secret(session, "graph.client_secret", s) is None
    assert secret_status(session, "graph.client_secret", s)["readable"] is False


def test_secret_store_validation(session, settings):
    with pytest.raises(SecretStoreError, match="SECRET_KEY"):
        set_secret(session, "graph.client_secret", SECRET, "admin", settings)
    settings.secret_key = SecretStr("k" * 40)
    with pytest.raises(SecretStoreError):
        set_secret(session, "graph.client_secret", "   ", "admin", settings)
    with pytest.raises(SecretStoreError, match="unknown"):
        set_secret(session, "other", "x", "admin", settings)


def test_id_settings_validation(session):
    assert set_value(session, "graph.tenant_id", TENANT.upper()) == TENANT
    assert set_value(session, "graph.tenant_id", "contoso.onmicrosoft.com") == "contoso.onmicrosoft.com"
    assert set_value(session, "graph.client_id", f" {CLIENT} ") == CLIENT
    for key, bad in (("graph.client_id", "not-a-guid"), ("graph.tenant_id", "bad tenant!")):
        with pytest.raises(SettingError):
            set_value(session, key, bad)


def test_credential_priority(session, s):
    assert graph_credentials(session, s).credential_source == "none"
    s.graph_tenant_id, s.graph_client_id = "env-tenant.onmicrosoft.com", CLIENT
    s.graph_client_secret = SecretStr("env-secret")
    c = graph_credentials(session, s)
    assert (c.tenant_id, c.credential_source, c.client_secret) == ("env-tenant.onmicrosoft.com", "environment-secret", "env-secret")
    s.graph_certificate_path = "/run/secrets/dmarc/graph-cert.pem"
    assert graph_credentials(session, s).credential_source == "environment-certificate"
    # Portal values win over the environment.
    set_value(session, "graph.tenant_id", TENANT)
    set_secret(session, "graph.client_secret", SECRET, "admin", s)
    c = graph_credentials(session, s)
    assert (c.tenant_id, c.client_id, c.client_secret, c.credential_source) == (TENANT, CLIENT, SECRET, "portal")
    assert SECRET not in repr(c)


def test_token_provider_requires_complete_config(session, s):
    with pytest.raises(GraphNotConfigured, match="tenant ID and client ID"):
        msal_token_provider(s, graph_credentials(session, s))
    set_value(session, "graph.tenant_id", TENANT)
    set_value(session, "graph.client_id", CLIENT)
    with pytest.raises(GraphNotConfigured, match="secret or certificate"):
        msal_token_provider(s, graph_credentials(session, s))


def test_worker_factory_picks_up_portal_changes(session, sessions, s, monkeypatch):
    from dmarc import worker

    built = []
    monkeypatch.setattr(worker, "msal_token_provider", lambda st, creds: built.append(creds.client_secret) or (lambda: "t"))
    set_value(session, "graph.tenant_id", TENANT)
    set_value(session, "graph.client_id", CLIENT)
    set_secret(session, "graph.client_secret", "first", "admin", s)
    session.commit()
    factory = worker.default_mailbox_factory(s, sessions)
    factory("dmarc@example.com").close()
    factory("dmarc@example.com").close()
    assert built == ["first"]  # token provider (and its cache) reused while nothing changes
    set_secret(session, "graph.client_secret", "second", "admin", s)
    session.commit()
    factory("dmarc@example.com").close()
    assert built == ["first", "second"]  # new secret used without restarting the worker


def test_graph_module_exports():
    assert graph_mod.GraphCredentials("t", "c", "secret").fingerprint != graph_mod.GraphCredentials("t", "c", "other").fingerprint
