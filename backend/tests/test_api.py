import csv
import io
from datetime import UTC, date, datetime

import pytest
from pydantic import SecretStr
from fastapi.testclient import TestClient
from sqlalchemy import select

from dmarc.api import auth as auth_mod
from dmarc.api.app import create_app
from dmarc.api.auth import hash_password
from dmarc.db import models as m
from dmarc.dnscheck.run import run_dns_checks
from dmarc.enrich import assign_sources, enrich_ips
from dmarc.geoip import GeoIp
from dmarc.senders import load_catalog
from dmarc.stats import rebuild_daily
from dmarc.storage import ingest_email
from tests.conftest import fixture_bytes

PASSWORD = "correct horse battery staple"


@pytest.fixture
def api_settings(settings):
    settings.secret_key = SecretStr("s" * 40)
    settings.cookie_secure = False
    settings.local_login_enabled = True
    settings.public_url = "https://dmarc.example.com"
    settings.analysis_days = 5000  # fixtures are from 2025
    settings.min_report_days = 1
    return settings


@pytest.fixture
def app(api_settings, sessions):
    auth_mod.login_limiter.hits.clear()
    return create_app(api_settings, sessions)


@pytest.fixture
def users(session):
    for name, role in (("admin", "admin"), ("viewer", "viewer")):
        session.add(m.User(subject=f"local:{name}", name=name, role=role, is_local=True, active=True,
                           failed_logins=0, password_hash=hash_password(PASSWORD)))
    session.commit()


def login(app, username="admin"):
    c = TestClient(app)
    r = c.post("/auth/local-login", json={"username": username, "password": PASSWORD})
    assert r.status_code == 200, r.text
    c.headers["X-CSRF-Token"] = c.get("/api/me").json()["csrf"]
    return c


@pytest.fixture
def admin(app, users):
    return login(app, "admin")


@pytest.fixture
def viewer(app, users):
    return login(app, "viewer")


@pytest.fixture
def data(session, settings, fake_dns, geoip_files):
    for name in ("google.eml", "microsoft.eml", "yahoo.eml", "mailru.eml"):
        ingest_email(session, fixture_bytes("rua", name), settings=settings)
    settings.ruf_store_body = False
    ingest_email(session, fixture_bytes("ruf", "arf_full.eml"), settings=settings)
    settings.ruf_store_body = True
    ingest_email(session, fixture_bytes("ruf", "arf_phishing.eml"), settings=settings)
    ingest_email(session, fixture_bytes("broken", "mixed.eml"), external_id="mixed", settings=settings)
    session.add(m.Domain(name="example.com"))
    session.commit()
    settings.geoip_dir = str(geoip_files)
    catalog = load_catalog()
    enrich_ips(session, fake_dns, GeoIp.from_settings(settings), catalog, settings, datetime(2025, 11, 26, tzinfo=UTC))
    assign_sources(session, catalog)
    run_dns_checks(session, settings, fake_dns, datetime(2025, 11, 26, tzinfo=UTC))
    rebuild_daily(session, date(2025, 1, 1), catalog)
    session.commit()


# --------------------------------------------------------------------------------------
# Authentication & security
# --------------------------------------------------------------------------------------

def test_health_and_unauthenticated(api_settings, sessions, tmp_path):
    api_settings.static_dir = str(tmp_path)  # no frontend build
    c = TestClient(create_app(api_settings, sessions))
    assert c.get("/healthz").json() == {"status": "ok"}
    assert c.get("/api/domains").status_code == 401
    assert c.get("/api/does-not-exist").status_code == 404
    assert c.get("/auth/config").json() == {"oidc": False, "local": True}
    r = c.get("/dashboard")
    assert r.status_code == 503  # frontend not built in tests
    for h in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"):
        assert h in r.headers


def test_secret_key_required(settings, sessions):
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app(settings, sessions)


def test_spa_fallback(api_settings, sessions, tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "app.js").write_text("console.log(1)")
    (tmp_path / "index.html").write_text("<html>app</html>")
    api_settings.static_dir = str(tmp_path)
    c = TestClient(create_app(api_settings, sessions))
    assert c.get("/sources").text == "<html>app</html>"
    assert c.get("/assets/app.js").text == "console.log(1)"
    assert c.get("/../../etc/passwd").text == "<html>app</html>"


def test_local_login_and_me(admin):
    me = admin.get("/api/me").json()
    assert me["role"] == "admin" and me["is_local"] and len(me["csrf"]) > 20


def test_wrong_password_and_lockout(app, users, session):
    c = TestClient(app)
    for _ in range(5):
        assert c.post("/auth/local-login", json={"username": "admin", "password": "nope"}).status_code == 401
    assert c.post("/auth/local-login", json={"username": "admin", "password": PASSWORD}).status_code == 423
    assert c.post("/auth/local-login", json={"username": "ghost", "password": "x"}).status_code == 401
    session.expire_all()
    assert session.scalars(select(m.AuditLog).where(m.AuditLog.action == "login_failed")).all()


def test_login_rate_limit(app, users):
    c = TestClient(app)
    codes = [c.post("/auth/local-login", json={"username": "ghost", "password": "x"}).status_code for _ in range(11)]
    assert codes[-1] == 429


def test_local_login_requires_json_and_can_be_disabled(app, users, api_settings):
    c = TestClient(app)
    r = c.post("/auth/local-login", data={"username": "admin", "password": PASSWORD})
    assert r.status_code in (415, 422)
    api_settings.local_login_enabled = False
    assert c.post("/auth/local-login", json={"username": "admin", "password": PASSWORD}).status_code == 404


def test_csrf_required(admin):
    token = admin.headers.pop("X-CSRF-Token")
    assert admin.post("/api/jobs/fetch").status_code == 403
    admin.headers["X-CSRF-Token"] = "wrong"
    assert admin.post("/api/jobs/fetch").status_code == 403
    admin.headers["X-CSRF-Token"] = token
    assert admin.post("/api/jobs/fetch").status_code == 202


def test_logout(admin):
    assert admin.post("/auth/logout").json() == {"redirect": "/login?logged_out=1"}
    assert admin.get("/api/me").status_code == 401


def test_disabled_user_is_logged_out(admin, session):
    u = session.scalars(select(m.User).where(m.User.subject == "local:admin")).one()
    u.active = False
    session.commit()
    assert admin.get("/api/me").status_code == 401


def test_viewer_permissions(viewer, data):
    assert viewer.get("/api/domains").status_code == 200
    assert viewer.get("/api/domains/example.com/dashboard").status_code == 200
    assert viewer.get("/api/records.csv?domain=example.com").status_code == 200
    for method, url, body in [
        ("put", "/api/settings/mailbox.poll_minutes", {"value": 5}),
        ("get", "/api/settings", None),
        ("post", "/api/jobs/fetch", None),
        ("get", "/api/forensic", None),
        ("get", "/api/users", None),
        ("post", "/api/domains", {"name": "example.org"}),
        ("put", "/api/domains/example.com/sources/sender:flowmailer/classification", {"status": "legit"}),
    ]:
        r = getattr(viewer, method)(url, **({"json": body} if body is not None else {}))
        assert r.status_code == 403, (url, r.status_code)


class FakeEntra:
    def __init__(self, claims):
        self.claims = claims

    async def authorize_redirect(self, request, redirect_uri):
        from fastapi.responses import RedirectResponse
        return RedirectResponse(f"https://login.example/authorize?redirect_uri={redirect_uri}")

    async def authorize_access_token(self, request):
        return {"userinfo": self.claims}


class FakeOAuth:
    def __init__(self, claims):
        self.client = FakeEntra(claims)

    def create_client(self, name):
        return self.client


def entra_claims(**kw):
    return {"tid": "tenant-1", "oid": "oid-1", "preferred_username": "jan@corp.example", "name": "Jan",
            "roles": ["DMARC.Viewer"]} | kw


def test_entra_sign_in(app, api_settings, session):
    api_settings.oidc_tenant_id = "tenant-1"
    api_settings.oidc_client_id = "client-1"
    api_settings.oidc_client_secret = SecretStr("secret")
    app.state.oauth = FakeOAuth(entra_claims())
    c = TestClient(app, follow_redirects=False)
    r = c.get("/auth/login")
    assert r.headers["location"] == "https://login.example/authorize?redirect_uri=https://dmarc.example.com/auth/callback"
    r = c.get("/auth/callback?code=x&state=y")
    assert r.status_code == 303 and r.headers["location"] == "/"
    me = c.get("/api/me").json()
    assert (me["role"], me["email"], me["is_local"]) == ("viewer", "jan@corp.example", False)

    # Role is updated from the token at every sign-in.
    app.state.oauth.client.claims = entra_claims(roles=["DMARC.Admin", "DMARC.Viewer"])
    c.get("/auth/callback?code=x&state=y")
    assert c.get("/api/me").json()["role"] == "admin"
    assert session.scalars(select(m.User).where(m.User.subject == "entra:tenant-1:oid-1")).one()

    c.headers["X-CSRF-Token"] = c.get("/api/me").json()["csrf"]
    out = c.post("/auth/logout").json()["redirect"]
    assert out.startswith("https://login.microsoftonline.com/tenant-1/oauth2/v2.0/logout?post_logout_redirect_uri=")


@pytest.mark.parametrize("claims", [entra_claims(roles=[]), entra_claims(tid="other-tenant")])
def test_entra_sign_in_denied(app, api_settings, claims):
    api_settings.oidc_tenant_id = "tenant-1"
    app.state.oauth = FakeOAuth(claims)
    c = TestClient(app, follow_redirects=False)
    r = c.get("/auth/callback?code=x&state=y")
    assert r.headers["location"] == "/login?error=no_access"
    assert c.get("/api/me").status_code == 401


def test_entra_error_callback(app, api_settings):
    api_settings.oidc_tenant_id = "tenant-1"
    app.state.oauth = FakeOAuth(entra_claims())
    c = TestClient(app, follow_redirects=False)
    assert c.get("/auth/callback?error=access_denied").headers["location"] == "/login?error=signin_failed"


# --------------------------------------------------------------------------------------
# Data
# --------------------------------------------------------------------------------------

def test_domains_and_dashboard(admin, data):
    [d] = admin.get("/api/domains").json()
    # google 1615 + microsoft 92 + yahoo 2 + mail.ru 1 + DMARCbis report from mixed.eml 10
    assert d["name"] == "example.com" and d["messages"] == 1720 and d["policy"] == "none"
    dash = admin.get("/api/domains/example.com/dashboard?days=730").json()
    assert dash["totals"]["messages"] == 1720
    assert dash["totals"]["dmarc_pass_pct"] == round(100 * 516 / 1720, 1)
    assert sum(p["messages"] for p in dash["trend"]) == 1720 and len(dash["trend"]) == 730
    assert dash["top_sources"][0]["name"] == "Flowmailer"
    assert dash["readiness"]["status"] == "not_ready"
    assert any(r["source_key"] == "sender:flowmailer" for r in dash["recommendations"])
    assert admin.get("/api/domains/unknown.example/dashboard").status_code == 404


def test_sources_and_classification(admin, data, session):
    sources = {s["key"]: s for s in admin.get("/api/domains/example.com/sources?days=730").json()}
    fm = sources["sender:flowmailer"]
    assert fm["messages"] == 1200 and fm["status"] is None and fm["asns"] == ["AS64501 Example ESP B.V."]
    assert fm["countries"] == ["NL"] and fm["ips"] == ["198.51.100.23"]
    r = admin.put("/api/domains/example.com/sources/sender:flowmailer/classification",
                  json={"status": "legit", "note": "Invoices"})
    assert r.status_code == 200
    fm = {s["key"]: s for s in admin.get("/api/domains/example.com/sources?days=730").json()}["sender:flowmailer"]
    assert (fm["status"], fm["note"], fm["classified_by"]) == ("legit", "Invoices", "admin")
    admin.put("/api/domains/example.com/sources/sender:flowmailer/classification", json={"status": None})
    assert session.scalars(select(m.SourceClassification)).all() == []
    assert admin.put("/api/domains/example.com/sources/x/classification", json={"status": "bogus"}).status_code == 422
    csv_text = admin.get("/api/domains/example.com/sources.csv?days=730").text
    assert csv_text.splitlines()[0].startswith("name,key,category,status,messages")


def test_records_filters_and_paging(admin, data):
    r = admin.get("/api/records?domain=example.com").json()
    assert r["total"] == 8 and r["messages"] == 1720
    fail = admin.get("/api/records?domain=example.com&result=fail").json()
    assert {i["source_ip"] for i in fail["items"]} == {"198.51.100.23", "203.0.113.77", "203.0.113.5"}
    assert fail["total"] == 3
    fm = admin.get("/api/records?source=sender:flowmailer").json()["items"][0]
    assert fm["source_name"] == "Flowmailer" and fm["ptr"] == "o1.mailer.flowmailer.net"
    assert {a["method"] for a in fm["auth"]} == {"spf", "dkim"}
    assert admin.get("/api/records?reporter=Yahoo").json()["total"] == 1
    assert admin.get("/api/records?ip=40.107.22.105").json()["total"] == 1
    assert admin.get("/api/records?ip=not-an-ip").status_code == 422
    # Microsoft and Mail.ru reports end exactly at 25 Nov 00:00 and overlap the range
    assert admin.get("/api/records?from=2025-11-25&to=2025-11-30").json()["total"] == 3
    page = admin.get("/api/records?page_size=3&page=3").json()
    assert len(page["items"]) == 2 and page["page"] == 3
    assert admin.get("/api/records?result=bogus").status_code == 422


def test_records_csv(admin, data, session):
    r = admin.get("/api/records.csv?domain=example.com&result=fail")
    assert r.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == 3 and {x["source"] for x in rows} >= {"Flowmailer"}
    assert any("mailer.esp-example.net/fm1=pass" in x["dkim_results"] for x in rows)
    assert session.scalars(select(m.AuditLog).where(m.AuditLog.action == "export")).first()


def test_csv_formula_injection_escaped():
    from dmarc.api.data import _csv_cell
    assert _csv_cell("=HYPERLINK(1)") == "'=HYPERLINK(1)" and _csv_cell("ok") == "ok" and _csv_cell(5) == 5


def test_reports(admin, data):
    reports = admin.get("/api/reports?domain=example.com").json()
    assert reports["total"] == 5  # google, microsoft, yahoo, mail.ru, DMARCbis
    g = next(x for x in reports["items"] if x["org_name"] == "google.com")
    assert (g["messages"], g["records"], g["dmarc_pass_pct"]) == (1615, 3, round(100 * 412 / 1615, 1))
    detail = admin.get(f"/api/reports/{g['id']}").json()
    assert detail["policy"]["p"] == "none" and detail["has_xml"] and detail["inbound"]["subject"].startswith("Report domain")
    xml = admin.get(f"/api/reports/{g['id']}/xml")
    assert xml.headers["content-type"] == "application/octet-stream" and b"<feedback>" in xml.content
    assert admin.get("/api/reports/999999").status_code == 404
    assert [x["org_name"] for x in admin.get("/api/reporters?domain=example.com").json()]


def test_ip_detail(admin, data):
    d = admin.get("/api/ips/40.107.22.105").json()
    assert d["info"]["sender"] == "Microsoft 365 (Exchange Online)" and d["info"]["ptr_confirmed"]
    assert d["domains"][0]["spf_result"] == "pass"  # covered by include:spf.protection.outlook.com
    assert admin.get("/api/ips/198.51.100.23").json()["domains"][0]["spf_result"] == "fail"


def test_dns_endpoint(admin, data):
    d = admin.get("/api/domains/example.com/dns").json()
    assert d["latest"]["result"]["dmarc"]["effective_policy"] == "none" and len(d["history"]) == 1
    assert admin.post("/api/domains/example.com/dns/check").status_code == 202


def test_forensic_admin_only_and_audited(admin, data, session):
    items = admin.get("/api/forensic?domain=example.com").json()["items"]
    assert len(items) == 2
    plain = next(i for i in items if i["original_subject"] == "Urgent invoice")
    detail = admin.get(f"/api/forensic/{plain['id']}").json()
    assert detail["body_stored"] is False and ["Subject", "Urgent invoice"] in detail["original_headers"]
    assert detail["analysis"]["body"] is None and detail["reports_from_same_ip"] == 2
    assert session.scalars(select(m.AuditLog).where(m.AuditLog.action == "view_forensic")).first()


def test_forensic_analysis_api(admin, data):
    [ph] = admin.get("/api/forensic?q=invoice 2025").json()["items"]
    assert ph["body_stored"] and ph["as_org"] == "Example Bulletproof Hosting"
    d = admin.get(f"/api/forensic/{ph['id']}").json()
    a = d["analysis"]
    assert a["auth_summary"]["dkim"] == "pass" and a["body"]["attachments"][0]["filename"] == "invoice-2025-1187.pdf"
    hops = a["hops"]
    assert hops[0]["private"] is True and hops[1]["private"] is False  # 10.x internal, public sender not
    assert (hops[1]["ip"], hops[1]["as_org"], hops[1]["country"]) == ("203.0.113.66", "Example Bulletproof Hosting", "RU")
    assert any(x["code"] == "reply_to_foreign" for x in a["anomalies"])


def test_forensic_filters_and_campaigns(admin, data):
    assert admin.get("/api/forensic?ip=203.0.113.66").json()["total"] == 2
    assert admin.get("/api/forensic?ip=192.0.2.1").json()["total"] == 0
    assert admin.get("/api/forensic?ip=bad").status_code == 422
    camps = admin.get("/api/forensic/campaigns?domain=example.com").json()
    assert {c["subject"] for c in camps} == {"Urgent invoice", "Outstanding invoice 2025-1187"}
    assert all(c["reports"] == 1 and c["source_ip"] == "203.0.113.66" for c in camps)


def test_forensic_export(admin, data, session):
    [ph] = admin.get("/api/forensic?q=2025-1187").json()["items"]
    r = admin.get(f"/api/forensic/{ph['id']}/export.eml")
    assert r.headers["content-type"].startswith("message/rfc822") and "attachment" in r.headers["content-disposition"]
    assert b"j.jansen@receiver.example" not in r.content and b"(body not included)" in r.content
    assert b"invoice-2025-1187.pdf" in admin.get(f"/api/forensic/{ph['id']}/export.eml?include_body=true").content
    assert session.scalars(select(m.AuditLog).where(m.AuditLog.action == "export_forensic")).first()


def test_forensic_viewer_forbidden(viewer, data):
    assert viewer.get("/api/forensic/campaigns").status_code == 403
    assert viewer.get("/api/forensic/1/export.eml").status_code == 403


# --------------------------------------------------------------------------------------
# Management
# --------------------------------------------------------------------------------------

def test_settings(admin, session):
    s = admin.get("/api/settings").json()
    assert s["mailbox.address"]["source"] == "environment"
    r = admin.put("/api/settings/mailbox.address", json={"value": "dmarc@example.com"})
    assert r.json() == {"key": "mailbox.address", "value": "dmarc@example.com"}
    assert admin.get("/api/settings").json()["mailbox.address"]["updated_by"] == "admin"
    assert admin.put("/api/settings/mailbox.address", json={"value": "nope"}).status_code == 422
    assert admin.put("/api/settings/graph.client_secret", json={"value": "x"}).status_code == 422
    assert admin.delete("/api/settings/mailbox.address").json()["source"] == "environment"
    actions = [a.action for a in session.scalars(select(m.AuditLog).order_by(m.AuditLog.id))]
    assert "setting_change" in actions and "setting_reset" in actions


def test_domains_management(admin, session):
    assert admin.post("/api/domains", json={"name": "Example.com"}).json() == {"name": "example.com"}
    assert admin.post("/api/domains", json={"name": "example.com"}).status_code == 409
    assert admin.post("/api/domains", json={"name": "not a domain"}).status_code == 422
    assert admin.patch("/api/domains/example.com", json={"parked": True}).json()["parked"] is True
    assert session.scalars(select(m.JobRun).where(m.JobRun.job == "dnscheck", m.JobRun.status == "queued")).first()
    assert admin.delete("/api/domains/example.com").status_code == 204
    assert admin.get("/api/domains").json() == []


def test_inbound_and_jobs(admin, data):
    problems = admin.get("/api/inbound?status=problems").json()
    assert problems["total"] == 1 and problems["items"][0]["status"] == "partial"
    assert problems["items"][0]["report_ids"] and "bad.xml" in problems["items"][0]["errors"][0]
    assert admin.get("/api/inbound").json()["counts"]["processed"] >= 4
    assert admin.post("/api/jobs/fetch").json()["status"] == "queued"
    assert admin.post("/api/jobs/bogus").status_code == 404
    jobs = admin.get("/api/jobs").json()
    assert jobs["items"][0]["job"] == "fetch" and jobs["items"][0]["requested_by"] == "admin"


def test_users_and_audit(admin, viewer, session):
    users = {u["name"]: u for u in admin.get("/api/users").json()}
    assert admin.patch(f"/api/users/{users['admin']['id']}", json={"active": False}).status_code == 422
    assert admin.patch(f"/api/users/{users['viewer']['id']}", json={"role": "admin"}).json()["role"] == "admin"
    session.add(m.User(subject="entra:t:o", email="x@y.z", role="viewer", is_local=False, active=True, failed_logins=0))
    session.commit()
    entra = next(u for u in admin.get("/api/users").json() if u["email"] == "x@y.z")
    assert admin.patch(f"/api/users/{entra['id']}", json={"role": "admin"}).status_code == 422
    assert admin.patch(f"/api/users/{entra['id']}", json={"active": False}).json()["active"] is False
    log = admin.get("/api/audit").json()
    assert log["total"] >= 3 and {"login", "user_update"} <= {x["action"] for x in log["items"]}


def test_notifications_api(app, admin, viewer, session, mailbox_factory, fake_graph):
    assert viewer.post("/api/notifications/test").status_code == 403
    r = admin.post("/api/notifications/test")
    assert r.status_code == 422 and "no recipients" in r.json()["detail"]
    admin.put("/api/settings/notify.recipients", json={"value": "it@example.com, ciso@example.com"})
    admin.put("/api/settings/mailbox.address", json={"value": "dmarc@example.com"})
    app.state.mailbox_factory = mailbox_factory
    r = admin.post("/api/notifications/test")
    assert r.json() == {"sent_to": ["it@example.com", "ciso@example.com"]}
    assert fake_graph.sent[0]["message"]["subject"] == "Test notification from the DMARC portal"
    items = admin.get("/api/notifications").json()["items"]
    assert items[0]["kind"] == "test" and items[0]["sent_at"]
    assert viewer.get("/api/notifications").status_code == 403


GRAPH_SECRET = "Xy7~verySecretValue.123"


def test_graph_connection_admin(app, admin, viewer, session, monkeypatch, fake_graph):
    status = admin.get("/api/graph").json()
    assert status["ready"] is False and status["client_secret"]["stored"] is False
    assert admin.put("/api/settings/graph.tenant_id", json={"value": "11111111-2222-3333-4444-555555555555"}).status_code == 200
    assert admin.put("/api/settings/graph.client_id", json={"value": "66666666-7777-8888-9999-000000000000"}).status_code == 200
    r = admin.put("/api/graph/secret", json={"value": GRAPH_SECRET})
    assert r.status_code == 200 and GRAPH_SECRET not in r.text
    st = admin.get("/api/graph")
    assert GRAPH_SECRET not in st.text
    st = st.json()
    assert st["ready"] and st["credential_source"] == "portal"
    assert st["client_secret"]["stored"] and st["client_secret"]["readable"] and st["client_secret"]["updated_by"] == "admin"
    # The secret appears nowhere: not in settings, not in the audit log.
    assert GRAPH_SECRET not in admin.get("/api/settings").text
    assert GRAPH_SECRET not in admin.get("/api/audit").text
    assert "secret_set" in admin.get("/api/audit").text

    # Viewers can neither read the status nor change anything.
    assert viewer.get("/api/graph").status_code == 403
    assert viewer.put("/api/graph/secret", json={"value": "x"}).status_code == 403
    assert viewer.delete("/api/graph/secret").status_code == 403

    # Connection test with the stored credentials (token + Graph mocked).
    import httpx

    from dmarc import graph as graph_mod
    seen = []
    monkeypatch.setattr(graph_mod, "msal_token_provider", lambda s, creds: seen.append(creds) or (lambda: "token"))
    app.state.graph_http = httpx.Client(transport=fake_graph.transport())
    admin.put("/api/settings/mailbox.address", json={"value": "dmarc@example.com"})
    test = admin.post("/api/graph/test").json()
    assert test["ok"] and [x["step"] for x in test["steps"]][:2] == ["Access token", "Read access"]
    assert seen[0].client_secret == GRAPH_SECRET and seen[0].credential_source == "portal"

    assert admin.delete("/api/graph/secret").json()["client_secret"]["stored"] is False
    assert admin.put("/api/graph/secret", json={"value": ""}).status_code == 422
