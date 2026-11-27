"""Minimal Microsoft Graph client for reading and moving mail in one (shared) mailbox.

Authentication uses the OAuth2 client-credentials flow (app-only) with either a
certificate (recommended) or a client secret. Access to mailboxes must be restricted
in Exchange Online (RBAC for Applications), see docs/app-registratie.md.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import quote

import httpx

from dmarc.config import Settings, get_settings

log = logging.getLogger(__name__)

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
WELL_KNOWN_FOLDERS = {
    "inbox": "inbox",
    "postvak in": "inbox",
    "root": "msgfolderroot",
    "msgfolderroot": "msgfolderroot",
    "archive": "archive",
    "archief": "archive",
}
RETRY_STATUS = {429, 500, 502, 503, 504}


class GraphError(Exception):
    def __init__(self, message: str, status: int | None = None, code: str | None = None):
        super().__init__(message)
        self.status = status
        self.code = code


class GraphNotConfigured(GraphError):
    pass


class MessageTooLarge(GraphError):
    pass


@dataclass(frozen=True)
class GraphMessage:
    id: str
    internet_message_id: str | None
    subject: str | None
    sender: str | None
    received_at: datetime | None


# --------------------------------------------------------------------------------------
# Token provider
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class GraphCredentials:
    tenant_id: str | None
    client_id: str | None
    client_secret: str | None = field(default=None, repr=False)
    certificate_path: str | None = None
    credential_source: str = "none"  # portal | environment-certificate | environment-secret | none

    @property
    def fingerprint(self) -> str:
        import hashlib

        raw = f"{self.tenant_id}|{self.client_id}|{self.client_secret}|{self.certificate_path}"
        return hashlib.sha256(raw.encode()).hexdigest()


def graph_credentials(session, settings: Settings | None = None) -> GraphCredentials:
    """Effective credentials: values entered in the admin portal win over the environment.

    Credential order: client secret stored in the portal, then DMARC_GRAPH_CERTIFICATE_PATH,
    then DMARC_GRAPH_CLIENT_SECRET.
    """
    from dmarc.appsettings import get_all
    from dmarc.secrets_store import get_secret

    s = settings or get_settings()
    values = get_all(session, s)
    tenant, client = values["graph.tenant_id"]["value"], values["graph.client_id"]["value"]
    stored = get_secret(session, "graph.client_secret", s)
    if stored:
        return GraphCredentials(tenant, client, stored, None, "portal")
    if s.graph_certificate_path:
        return GraphCredentials(tenant, client, None, s.graph_certificate_path, "environment-certificate")
    if s.graph_client_secret:
        return GraphCredentials(tenant, client, s.graph_client_secret.get_secret_value(), None, "environment-secret")
    return GraphCredentials(tenant, client, None, None, "none")


def msal_token_provider(settings: Settings, creds: GraphCredentials | None = None) -> Callable[[], str]:
    """Return a callable that yields a (cached) app-only access token."""
    import msal

    if creds is None:  # environment only (no database), e.g. scripts
        secret = settings.graph_client_secret.get_secret_value() if settings.graph_client_secret else None
        creds = GraphCredentials(settings.graph_tenant_id, settings.graph_client_id, secret,
                                 settings.graph_certificate_path,
                                 "environment-certificate" if settings.graph_certificate_path else "environment-secret")
    if not (creds.tenant_id and creds.client_id):
        raise GraphNotConfigured("Graph tenant ID and client ID are not set (Settings > Microsoft 365 connection)")

    if creds.certificate_path and not creds.client_secret:
        credential = _certificate_credential(settings, creds.certificate_path)
    elif creds.client_secret:
        credential = creds.client_secret
    else:
        raise GraphNotConfigured("no Graph client secret or certificate configured (Settings > Microsoft 365 connection)")

    app = msal.ConfidentialClientApplication(
        client_id=creds.client_id,
        client_credential=credential,
        authority=f"{settings.graph_authority_host.rstrip('/')}/{creds.tenant_id}",
    )

    def get_token() -> str:
        result = app.acquire_token_for_client(scopes=[GRAPH_SCOPE])  # cached by msal until expiry
        if "access_token" not in result:
            desc = (result.get("error_description") or "").splitlines()
            raise GraphError(f"token request failed: {result.get('error')}: {desc[0] if desc else ''}",
                             code=result.get("error"))
        return result["access_token"]

    return get_token


def _certificate_credential(settings: Settings, path: str) -> dict[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    pem = open(path, "rb").read()
    password = settings.graph_certificate_password.get_secret_value().encode() if settings.graph_certificate_password else None
    key = serialization.load_pem_private_key(pem, password=password)
    cert = x509.load_pem_x509_certificate(pem)
    return {
        "private_key": key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode(),
        "thumbprint": cert.fingerprint(hashes.SHA1()).hex(),  # noqa: S324 - required by Entra ID (x5t)
        "public_certificate": cert.public_bytes(serialization.Encoding.PEM).decode(),
    }


# --------------------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------------------

class GraphMailbox:
    def __init__(
        self,
        mailbox: str,
        token_provider: Callable[[], str],
        settings: Settings | None = None,
        http: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
        max_retries: int = 5,
    ):
        self.settings = settings or get_settings()
        self.mailbox = mailbox
        self._token = token_provider
        self._http = http or httpx.Client(timeout=self.settings.graph_timeout_seconds)
        self._sleep = sleep
        self._max_retries = max_retries
        self._base = f"{self.settings.graph_base_url.rstrip('/')}/users/{quote(mailbox)}"
        self._folder_cache: dict[str, str] = {}

    def close(self) -> None:
        self._http.close()

    # -- low level ----------------------------------------------------------------------

    def _request(self, method: str, url: str, *, stream_limit: int | None = None, **kw: Any) -> httpx.Response | bytes:
        if not url.startswith("http"):
            url = self._base + url
        refreshed = False
        for attempt in range(1, self._max_retries + 1):
            headers = {"Authorization": f"Bearer {self._token()}", **kw.pop("headers", {})}
            try:
                if stream_limit is not None:
                    with self._http.stream(method, url, headers=headers, **kw) as resp:
                        if resp.status_code < 400:
                            return _read_limited(resp, stream_limit)
                        resp.read()
                else:
                    resp = self._http.request(method, url, headers=headers, **kw)
            except httpx.TransportError as exc:
                if attempt == self._max_retries:
                    raise GraphError(f"network error talking to Graph: {exc}") from exc
                self._sleep(min(2 ** attempt, 30))
                continue

            if resp.status_code < 400:
                return resp
            if resp.status_code == 401 and not refreshed:
                refreshed = True  # token may have just expired; msal will fetch a new one
                continue
            if resp.status_code in RETRY_STATUS and attempt < self._max_retries:
                delay = _retry_after(resp) or min(2 ** attempt, 60)
                log.warning("Graph %s %s -> %s, retrying in %.0fs", method, url, resp.status_code, delay)
                self._sleep(delay)
                continue
            raise _error_from(resp)
        raise GraphError("Graph request failed after retries")

    def _get_json(self, url: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        return self._request("GET", url, params=params).json()

    # -- folders ------------------------------------------------------------------------

    def _child_folder(self, parent_id: str, name: str, create: bool) -> str | None:
        escaped = name.replace("'", "''")
        data = self._get_json(
            f"/mailFolders/{parent_id}/childFolders",
            {"$filter": f"displayName eq '{escaped}'", "$select": "id,displayName"},
        )
        for f in data.get("value", []):
            if f.get("displayName", "").lower() == name.lower():
                return f["id"]
        if not create:
            return None
        log.info("creating mail folder %r in %s", name, self.mailbox)
        try:
            resp = self._request("POST", f"/mailFolders/{parent_id}/childFolders", json={"displayName": name})
        except GraphError as exc:
            if exc.status == 409:  # created concurrently
                return self._child_folder(parent_id, name, create=False)
            raise
        return resp.json()["id"]

    def resolve_folder(self, path: str, create: bool = False) -> str:
        """Resolve 'Inbox', 'Verwerkt' or 'Inbox/DMARC/Verwerkt' to a folder id.

        A path whose first segment is a well-known folder (Inbox, Archive) starts there;
        otherwise the path is relative to the mailbox root.
        """
        key = f"{path.lower()}|{create}"
        if key in self._folder_cache:
            return self._folder_cache[key]
        segments = [s.strip() for s in path.strip("/").split("/") if s.strip()]
        if not segments:
            raise GraphError("empty folder path")
        first = WELL_KNOWN_FOLDERS.get(segments[0].lower())
        if first:
            current = self._get_json(f"/mailFolders/{first}", {"$select": "id"})["id"]
            segments = segments[1:]
        else:
            current = self._get_json("/mailFolders/msgfolderroot", {"$select": "id"})["id"]
        for seg in segments:
            nxt = self._child_folder(current, seg, create)
            if nxt is None:
                raise GraphError(f"mail folder {path!r} not found in {self.mailbox}", status=404)
            current = nxt
        self._folder_cache[key] = current
        return current

    # -- messages -----------------------------------------------------------------------

    def list_messages(self, folder_id: str, limit: int) -> Iterator[GraphMessage]:
        url: str | None = f"/mailFolders/{folder_id}/messages"
        params: dict[str, str] | None = {
            "$select": "id,internetMessageId,subject,from,receivedDateTime",
            "$orderby": "receivedDateTime asc",
            "$top": str(min(limit, 100)),
        }
        seen = 0
        while url and seen < limit:
            data = self._get_json(url, params)
            params = None  # nextLink already carries the query
            for item in data.get("value", []):
                yield _to_message(item)
                seen += 1
                if seen >= limit:
                    return
            url = data.get("@odata.nextLink")

    def get_mime(self, message_id: str) -> bytes:
        return self._request(
            "GET", f"/messages/{quote(message_id, safe='')}/$value",
            stream_limit=self.settings.max_message_bytes,
        )

    def move(self, message_id: str, folder_id: str) -> str:
        resp = self._request("POST", f"/messages/{quote(message_id, safe='')}/move", json={"destinationId": folder_id})
        return resp.json().get("id", message_id)

    def send_mail(self, message: dict[str, Any], save_to_sent: bool = True) -> None:
        self._request("POST", "/sendMail", json={"message": message, "saveToSentItems": save_to_sent})


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------

def _read_limited(resp: httpx.Response, limit: int) -> bytes:
    declared = resp.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise MessageTooLarge(f"message of {declared} bytes exceeds limit of {limit}")
    buf = bytearray()
    for chunk in resp.iter_bytes():
        buf += chunk
        if len(buf) > limit:
            raise MessageTooLarge(f"message exceeds limit of {limit} bytes")
    return bytes(buf)


def _retry_after(resp: httpx.Response) -> float | None:
    v = resp.headers.get("retry-after")
    try:
        return min(float(v), 300.0) if v else None
    except ValueError:
        return None


def _error_from(resp: httpx.Response) -> GraphError:
    code = message = None
    try:
        err = resp.json().get("error", {})
        code, message = err.get("code"), err.get("message")
    except ValueError:
        pass
    hint = ""
    if resp.status_code == 403 or code == "ErrorAccessDenied":
        hint = " (check the Exchange RBAC for Applications scope for this mailbox)"
    elif resp.status_code == 404 and code in ("ErrorInvalidUser", "MailboxNotEnabledForRESTAPI", "ResourceNotFound"):
        hint = " (check the mailbox address)"
    return GraphError(f"Graph error {resp.status_code} {code or ''}: {message or resp.text[:200]}{hint}", resp.status_code, code)


def _to_message(item: dict[str, Any]) -> GraphMessage:
    sender = None
    addr = (item.get("from") or {}).get("emailAddress") or {}
    if addr:
        name, mail = addr.get("name"), addr.get("address")
        sender = f"{name} <{mail}>" if name and name != mail else mail
    received = item.get("receivedDateTime")
    return GraphMessage(
        id=item["id"],
        internet_message_id=item.get("internetMessageId"),
        subject=item.get("subject"),
        sender=sender,
        received_at=datetime.fromisoformat(received.replace("Z", "+00:00")) if received else None,
    )
