import httpx
import pytest

from dmarc.graph import GraphError, GraphMailbox, MessageTooLarge
from tests.fake_graph import FakeGraph


def client(fake: FakeGraph, settings, sleeps=None, token=lambda: "t"):
    return GraphMailbox(fake.mailbox, token, settings, http=httpx.Client(transport=fake.transport()),
                        sleep=(sleeps.append if sleeps is not None else (lambda s: None)))


def test_resolve_and_create_folders(settings):
    fake = FakeGraph()
    c = client(fake, settings)
    assert c.resolve_folder("Inbox") == "inbox-id"
    assert c.resolve_folder("postvak in") == "inbox-id"
    with pytest.raises(GraphError) as exc:
        c.resolve_folder("Verwerkt")
    assert exc.value.status == 404
    fid = c.resolve_folder("Verwerkt", create=True)
    assert fake.folders[fid] == {"name": "Verwerkt", "parent": "root-id", "wk": None}
    assert c.resolve_folder("Verwerkt", create=True) == fid  # cached / found, not created twice
    nested = c.resolve_folder("Inbox/DMARC/Fout", create=True)
    assert fake.folders[nested]["name"] == "Fout"
    assert fake.folders[fake.folders[nested]["parent"]]["parent"] == "inbox-id"


def test_folder_name_with_quote(settings):
    fake = FakeGraph()
    c = client(fake, settings)
    fid = c.resolve_folder("Rick's reports", create=True)
    c._folder_cache.clear()
    assert c.resolve_folder("Rick's reports") == fid


def test_list_messages_paging_and_limit(settings):
    fake = FakeGraph()
    for i in range(250):
        fake.add_message(b"x", received=f"2025-11-25T{i // 60:02d}:{i % 60:02d}:00Z")
    c = client(fake, settings)
    msgs = list(c.list_messages("inbox-id", 230))
    assert len(msgs) == 230
    assert msgs[0].received_at < msgs[-1].received_at
    assert msgs[0].sender == "Reporter <reporter@example.org>"


def test_download_mime(settings):
    fake = FakeGraph()
    mid = fake.add_message(b"From: a@b\r\n\r\nhello")
    assert client(fake, settings).get_mime(mid) == b"From: a@b\r\n\r\nhello"


def test_download_size_limit(settings):
    fake = FakeGraph()
    mid = fake.add_message(b"x" * 5000)
    settings.max_message_bytes = 1000
    with pytest.raises(MessageTooLarge):
        client(fake, settings).get_mime(mid)


def test_retry_on_throttling(settings):
    fake = FakeGraph(throttle_next=2)
    sleeps = []
    assert client(fake, settings, sleeps).resolve_folder("Inbox") == "inbox-id"
    assert sleeps == [1.0, 1.0]  # honours Retry-After


def test_gives_up_after_max_retries(settings):
    fake = FakeGraph(throttle_next=99)
    with pytest.raises(GraphError) as exc:
        client(fake, settings).resolve_folder("Inbox")
    assert exc.value.status == 429


def test_access_denied_hint(settings):
    fake = FakeGraph(deny=True)
    with pytest.raises(GraphError, match="RBAC for Applications") as exc:
        client(fake, settings).resolve_folder("Inbox")
    assert exc.value.status == 403


def test_unknown_mailbox(settings):
    fake = FakeGraph()
    c = GraphMailbox("wrong@example.com", lambda: "t", settings, http=httpx.Client(transport=fake.transport()))
    with pytest.raises(GraphError, match="mailbox address"):
        c.resolve_folder("Inbox")


def test_401_refreshes_token_once(settings):
    fake = FakeGraph()
    calls = []
    real = fake.handle

    def handler(req):
        calls.append(req.headers["authorization"])
        if len(calls) == 1:
            return httpx.Response(401, json={"error": {"code": "InvalidAuthenticationToken"}})
        return real(req)

    tokens = iter(["old", "new"])
    c = GraphMailbox(fake.mailbox, lambda: next(tokens), settings, http=httpx.Client(transport=httpx.MockTransport(handler)))
    assert c.resolve_folder("Inbox") == "inbox-id"
    assert calls == ["Bearer old", "Bearer new"]


def test_not_configured(settings):
    from dmarc.graph import GraphNotConfigured, msal_token_provider

    with pytest.raises(GraphNotConfigured):
        msal_token_provider(settings)
    settings.graph_tenant_id = "t"
    settings.graph_client_id = "c"
    with pytest.raises(GraphNotConfigured, match="secret or certificate"):
        msal_token_provider(settings)
