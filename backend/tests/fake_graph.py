"""In-memory fake of the Microsoft Graph mail endpoints used by dmarc.graph."""

from __future__ import annotations

import itertools
import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlparse

import httpx

BASE = "https://graph.microsoft.com/v1.0"


@dataclass
class FakeMessage:
    id: str
    folder: str
    mime: bytes
    subject: str
    sender: str
    received: str


@dataclass
class FakeGraph:
    mailbox: str = "dmarc@example.com"
    folders: dict[str, dict] = field(default_factory=dict)
    messages: dict[str, FakeMessage] = field(default_factory=dict)
    fail_download: set[str] = field(default_factory=set)
    fail_move: set[str] = field(default_factory=set)
    throttle_next: int = 0  # number of upcoming requests answered with 429
    deny: bool = False
    requests: list[httpx.Request] = field(default_factory=list)
    sent: list[dict] = field(default_factory=list)
    fail_send: bool = False
    _ids: itertools.count = field(default_factory=lambda: itertools.count(1))

    def __post_init__(self):
        self.folders = {
            "root-id": {"name": "Top of Information Store", "parent": None, "wk": "msgfolderroot"},
            "inbox-id": {"name": "Inbox", "parent": "root-id", "wk": "inbox"},
        }

    # -- helpers for tests -------------------------------------------------------------

    def add_message(self, mime: bytes, subject: str = "Report", folder: str = "inbox-id",
                    received: str | None = None) -> str:
        n = next(self._ids)
        mid = f"msg-{n}"
        self.messages[mid] = FakeMessage(mid, folder, mime, subject, "reporter@example.org",
                                         received or f"2025-11-25T06:{n % 60:02d}:00Z")
        return mid

    def folder_named(self, name: str) -> str | None:
        return next((fid for fid, f in self.folders.items() if f["name"] == name), None)

    def in_folder(self, name: str) -> list[FakeMessage]:
        fid = self.folder_named(name)
        return [m for m in self.messages.values() if m.folder == fid]

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    # -- request handling --------------------------------------------------------------

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.headers.get("authorization", "").startswith("Bearer ")
        if self.throttle_next:
            self.throttle_next -= 1
            return httpx.Response(429, headers={"Retry-After": "1"}, json={"error": {"code": "TooManyRequests"}})
        if self.deny:
            return _err(403, "ErrorAccessDenied", "Access is denied.")

        url = urlparse(str(request.url))
        prefix = f"/v1.0/users/{self.mailbox}"
        path = unquote(url.path)
        if not path.startswith(prefix):
            return _err(404, "ErrorInvalidUser", "The requested user is invalid.")
        path = path[len(prefix):]
        q = {k: v[0] for k, v in parse_qs(url.query).items()}

        if m := re.fullmatch(r"/mailFolders/([^/]+)", path):
            fid = self._folder_id(m[1])
            return httpx.Response(200, json={"id": fid}) if fid else _err(404, "ErrorItemNotFound", "no folder")

        if m := re.fullmatch(r"/mailFolders/([^/]+)/childFolders", path):
            parent = self._folder_id(m[1])
            if request.method == "POST":
                name = json.loads(request.content)["displayName"]
                fid = f"folder-{next(self._ids)}"
                self.folders[fid] = {"name": name, "parent": parent, "wk": None}
                return httpx.Response(201, json={"id": fid, "displayName": name})
            wanted = re.search(r"displayName eq '(.*)'", q.get("$filter", ""))
            name = wanted[1].replace("''", "'") if wanted else None
            items = [{"id": fid, "displayName": f["name"]} for fid, f in self.folders.items()
                     if f["parent"] == parent and (name is None or f["name"] == name)]
            return httpx.Response(200, json={"value": items})

        if m := re.fullmatch(r"/mailFolders/([^/]+)/messages", path):
            fid = self._folder_id(m[1])
            msgs = sorted((x for x in self.messages.values() if x.folder == fid), key=lambda x: x.received)
            top, skip = int(q.get("$top", "10")), int(q.get("$skip", "0"))
            page = msgs[skip: skip + top]
            body = {"value": [{
                "id": x.id, "subject": x.subject, "internetMessageId": f"<{x.id}@example.org>",
                "receivedDateTime": x.received,
                "from": {"emailAddress": {"name": "Reporter", "address": x.sender}},
            } for x in page]}
            if skip + top < len(msgs):
                body["@odata.nextLink"] = f"{BASE}/users/{self.mailbox}/mailFolders/{m[1]}/messages?$top={top}&$skip={skip + top}"
            return httpx.Response(200, json=body)

        if m := re.fullmatch(r"/messages/([^/]+)/\$value", path):
            msg = self.messages.get(m[1])
            if msg is None:
                return _err(404, "ErrorItemNotFound", "not found")
            if msg.id in self.fail_download:
                return _err(503, "ServiceUnavailable", "try later")
            return httpx.Response(200, content=msg.mime, headers={"content-type": "text/plain"})

        if m := re.fullmatch(r"/messages/([^/]+)/move", path):
            msg = self.messages.pop(m[1], None)
            if msg is None:
                return _err(404, "ErrorItemNotFound", "not found")
            if msg.id in self.fail_move:
                self.messages[msg.id] = msg
                return _err(400, "ErrorMoveCopyFailed", "move failed")
            msg.folder = json.loads(request.content)["destinationId"]
            msg.id = f"{msg.id}-moved"  # Graph assigns a new id after a move
            self.messages[msg.id] = msg
            return httpx.Response(201, json={"id": msg.id})

        if path == "/sendMail" and request.method == "POST":
            if self.fail_send:
                return _err(403, "ErrorAccessDenied", "Access is denied.")
            self.sent.append(json.loads(request.content))
            return httpx.Response(202)

        return _err(400, "BadRequest", f"unhandled {request.method} {path}")

    def _folder_id(self, ref: str) -> str | None:
        if ref in self.folders:
            return ref
        return next((fid for fid, f in self.folders.items() if f["wk"] == ref), None)


def _err(status: int, code: str, message: str) -> httpx.Response:
    return httpx.Response(status, json={"error": {"code": code, "message": message}})
