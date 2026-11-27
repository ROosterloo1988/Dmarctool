"""Analysis of stored failure reports (RUF): authentication results, DKIM signatures, the
Received chain, header anomalies, links and attachments, and an anonymised export.

Safety: the original message is only *parsed*. Links are never fetched, attachments are never
decoded beyond hashing their bytes, and HTML is never rendered (only converted to text).
"""

from __future__ import annotations

import email
import email.policy
import email.utils
import hashlib
import html
import ipaddress
import re
from collections import Counter
from email.message import Message
from typing import Any

from dmarc.parsing.alignment import normalize_domain, organizational_domain

MAX_URLS = 50
MAX_TEXT = 8000
MAX_HOPS = 30

_URL = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"'()\[\]{}]+""")
_HREF = re.compile(r"""(?i)href\s*=\s*["']?([^"'\s>]+)""")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?i)(?:IPv6:)?((?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4})")
_TAG = re.compile(r"<[^>]+>")


# --------------------------------------------------------------------------------------
# Header helpers
# --------------------------------------------------------------------------------------

def _headers(report_headers: list[list[str]], name: str) -> list[str]:
    n = name.lower()
    return [v for k, v in report_headers if k.lower() == n]


def _first(report_headers: list[list[str]], name: str) -> str | None:
    vals = _headers(report_headers, name)
    return vals[0] if vals else None


def _addr_domain(value: str | None) -> str | None:
    if not value:
        return None
    _, addr = email.utils.parseaddr(value)
    if not addr or "@" not in addr:
        m = re.search(r"[\w.+-]+@([\w.-]+)", value)
        return normalize_domain(m.group(1)) if m else None
    return normalize_domain(addr.rsplit("@", 1)[1])


# --------------------------------------------------------------------------------------
# Authentication-Results (RFC 8601) and DKIM-Signature
# --------------------------------------------------------------------------------------

def parse_authentication_results(value: str | None) -> dict[str, Any]:
    """'mx.example; spf=pass smtp.mailfrom=a.example; dkim=fail (reason) header.d=b.example'"""
    out: dict[str, Any] = {"authserv_id": None, "results": []}
    if not value:
        return out
    # Remove comments in parentheses (not nested deeper than one level in practice).
    text = re.sub(r"\([^()]*\)", " ", value)
    parts = [p.strip() for p in text.split(";")]
    if parts and parts[0] and "=" not in parts[0].split()[0]:
        out["authserv_id"] = parts[0].split()[0]  # optional version number after it is ignored
        parts = parts[1:]
    for p in parts:
        tokens = p.split()
        if not tokens or "=" not in tokens[0]:
            continue
        method, result = tokens[0].split("=", 1)
        props = {}
        for t in tokens[1:]:
            if "=" in t:
                k, v = t.split("=", 1)
                props[k.lower()] = v.strip('"')
        out["results"].append({"method": method.lower(), "result": result.lower(), "props": props})
    return out


def parse_dkim_signature(value: str) -> dict[str, str]:
    tags = {}
    for part in value.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip().lower()
            if k in ("v", "a", "d", "s", "i", "c", "t", "x", "h"):
                tags[k] = "".join(v.split())[:200]
    return tags


# --------------------------------------------------------------------------------------
# Received chain
# --------------------------------------------------------------------------------------

def _first_ip(text: str) -> str | None:
    candidates = re.findall(r"\[([^\]]+)\]", text) + re.findall(r"\(([^()]*)\)", text)
    for c in candidates + [text]:
        for m in _IPV4.finditer(c):
            try:
                ip = ipaddress.ip_address(m.group(0))
                if not (ip.is_loopback or ip.is_unspecified):
                    return str(ip)
            except ValueError:
                continue
        for m in _IPV6.finditer(c):
            try:
                ip = ipaddress.ip_address(m.group(1))
                if not (ip.is_loopback or ip.is_unspecified):
                    return str(ip.ipv4_mapped or ip)
            except ValueError:
                continue
    return None


def parse_received(values: list[str]) -> list[dict[str, Any]]:
    """Hops from the original sender to the receiver (oldest first)."""
    hops = []
    for raw in reversed(values[:MAX_HOPS]):  # headers are prepended: last = first hop
        text = " ".join(raw.split())
        body, _, date = text.rpartition(";") if ";" in text else (text, "", "")
        frm = re.search(r"\bfrom\s+(.+?)(?=\s+by\s|\s+with\s|\s+id\s|\s+for\s|$)", body, re.I)
        by = re.search(r"\bby\s+(\S+)", body, re.I)
        with_ = re.search(r"\bwith\s+(\S+)", body, re.I)
        helo = re.search(r"\bhelo[= ]+([^\s)]+)", body, re.I)
        from_part = frm.group(1) if frm else ""
        hops.append({
            "from": from_part.split()[0] if from_part else None,
            "helo": helo.group(1) if helo else None,
            "ip": _first_ip(from_part) if from_part else None,
            "by": by.group(1) if by else None,
            "with": with_.group(1) if with_ else None,
            "date": date.strip() or None,
            "raw": text[:600],
        })
    return hops


# --------------------------------------------------------------------------------------
# Body: links, attachments, text
# --------------------------------------------------------------------------------------

def _unfold(value: str) -> str:
    return re.sub(r"\s*[\r\n]+\s*", " ", value).strip()


def rebuild_message(report_headers: list[list[str]], body: bytes) -> Message:
    head = "".join(f"{k}: {_unfold(v)}\r\n" for k, v in report_headers)
    return email.message_from_bytes(head.encode("utf-8", errors="replace") + b"\r\n" + body,
                                    policy=email.policy.compat32)


def defang(url: str) -> str:
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]", 1)


def _url_host(url: str) -> str | None:
    u = url if "://" in url else "http://" + url
    m = re.match(r"(?i)[a-z][a-z0-9+.-]*://(?:[^@/]*@)?([^/:?#]+)", u)
    return normalize_domain(m.group(1)) if m else None


def analyse_body(report_headers: list[list[str]], body: bytes | None) -> dict[str, Any] | None:
    if body is None:
        return None
    msg = rebuild_message(report_headers, body)
    urls: list[str] = []
    attachments, texts = [], []
    html_only: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        filename = part.get_filename()
        disposition = (part.get("Content-Disposition") or "").lower()
        payload = part.get_payload(decode=True) or b""
        if filename or "attachment" in disposition or not ctype.startswith("text/"):
            attachments.append({
                "filename": filename, "content_type": ctype, "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest() if payload else None,
            })
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            text = payload.decode(charset, errors="replace")
        except LookupError:
            text = payload.decode("utf-8", errors="replace")
        if ctype == "text/html":
            urls += [html.unescape(u) for u in _HREF.findall(text)]
            plain = html.unescape(_TAG.sub(" ", re.sub(r"(?is)<(script|style).*?</\1>", " ", text)))
            html_only.append(re.sub(r"[ \t]+", " ", plain))
        else:
            texts.append(text)
        urls += _URL.findall(text)

    seen, clean = set(), []
    for u in urls:
        u = u.strip().rstrip(".,;")
        if u.lower().startswith(("mailto:", "cid:", "#", "tel:")) or u in seen:
            continue
        seen.add(u)
        clean.append(u)
    domains = Counter(h for h in (_url_host(u) for u in clean) if h)
    text = "\n".join(texts) if texts else "\n".join(html_only)
    text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text).strip()
    return {
        "text": text[:MAX_TEXT], "text_truncated": len(text) > MAX_TEXT,
        "urls": [{"url": defang(u)[:500], "domain": _url_host(u)} for u in clean[:MAX_URLS]],
        "url_count": len(clean), "link_domains": dict(domains.most_common(20)),
        "attachments": attachments[:30],
    }


# --------------------------------------------------------------------------------------
# Anomalies
# --------------------------------------------------------------------------------------

def anomalies(report_headers: list[list[str]], reported_domain: str | None,
              link_domains: dict[str, int] | None) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    from_value = _first(report_headers, "From")
    from_domain = _addr_domain(from_value) or reported_domain
    org = organizational_domain(from_domain) if from_domain else None

    def foreign(d: str | None) -> bool:
        return bool(d and org and organizational_domain(d) != org)

    reply_to = _first(report_headers, "Reply-To")
    if foreign(_addr_domain(reply_to)):
        out.append({"severity": "critical", "code": "reply_to_foreign",
                    "text": f"Reply-To points to another domain ({_addr_domain(reply_to)}): replies go to the sender, a classic phishing sign."})
    return_path = _first(report_headers, "Return-Path")
    if foreign(_addr_domain(return_path)):
        out.append({"severity": "warning", "code": "return_path_foreign",
                    "text": f"Return-Path ({_addr_domain(return_path)}) is not your domain: bounces go elsewhere and SPF cannot align."})
    if from_value:
        name, addr = email.utils.parseaddr(from_value)
        embedded = re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", name or "")
        if embedded and embedded[0].lower() != (addr or "").lower():
            out.append({"severity": "critical", "code": "display_name_spoof",
                        "text": f"The display name contains another address ({embedded[0]}) than the real sender ({addr})."})
    msgid = _first(report_headers, "Message-ID")
    if foreign(_addr_domain(msgid)):
        out.append({"severity": "info", "code": "message_id_foreign",
                    "text": f"The Message-ID was generated by {_addr_domain(msgid)}, not by your domain."})
    for h in ("X-Mailer", "User-Agent"):
        v = _first(report_headers, h)
        if v:
            out.append({"severity": "info", "code": "mailer", "text": f"Sent with: {v[:200]}"})
    foreign_links = [d for d in (link_domains or {}) if foreign(d)]
    if foreign_links:
        out.append({"severity": "warning", "code": "foreign_links",
                    "text": f"Links point to other domains: {', '.join(foreign_links[:5])}."})
    return out


# --------------------------------------------------------------------------------------
# Full analysis
# --------------------------------------------------------------------------------------

def analyse(report_headers: list[list[str]], body: bytes | None, authentication_results: str | None,
            reported_domain: str | None) -> dict[str, Any]:
    ar_values = [authentication_results] if authentication_results else []
    ar_values += _headers(report_headers, "Authentication-Results")
    auth, seen = [], set()
    for v in ar_values:
        parsed = parse_authentication_results(v)
        unique = []
        for r in parsed["results"]:  # the ARF field usually repeats the header: show each result once
            sig = (r["method"], r["result"], tuple(sorted(r["props"].items())))
            if sig not in seen:
                seen.add(sig)
                unique.append(r)
        if unique:
            auth.append({"authserv_id": parsed["authserv_id"], "results": unique})
    summary: dict[str, str] = {}
    for a in auth:
        for r in a["results"]:
            summary.setdefault(r["method"], r["result"])
    body_info = analyse_body(report_headers, body)
    return {
        "auth": auth,
        "auth_summary": summary,
        "dkim_signatures": [parse_dkim_signature(v) for v in _headers(report_headers, "DKIM-Signature")],
        "hops": parse_received(_headers(report_headers, "Received")),
        "anomalies": anomalies(report_headers, reported_domain, body_info["link_domains"] if body_info else None),
        "body": body_info,
    }


# --------------------------------------------------------------------------------------
# Anonymised export
# --------------------------------------------------------------------------------------

RECIPIENT_HEADERS = {"to", "cc", "bcc", "delivered-to", "x-original-to", "envelope-to", "x-rcpt-to", "original-rcpt-to"}
_EMAIL = re.compile(r"([\w.+'-]+)@([\w-]+(?:\.[\w-]+)+)")


def _redact_addresses(value: str) -> str:
    return _EMAIL.sub(lambda m: f"redacted@{m.group(2)}", value)


def anonymised_eml(report_headers: list[list[str]], body: bytes | None, include_body: bool) -> bytes:
    """The original message with recipient addresses replaced by redacted@<their domain>.

    Sender-side information (From, Return-Path, Received hops of the sender, Message-ID) is kept,
    because that is what a provider or CERT needs to act on.
    """
    lines = []
    for k, v in report_headers:
        v = _unfold(v)
        lk = k.lower()
        if lk in RECIPIENT_HEADERS:
            v = _redact_addresses(v)
        elif lk == "received":
            v = re.sub(r"(?i)\bfor\s+<?[^>\s;]+>?", "for <redacted>", v)
        lines.append(f"{k}: {v}")
    lines.append("X-DMARC-Portal-Note: recipient addresses redacted")
    head = "\r\n".join(lines).encode("utf-8", errors="replace")
    if include_body and body:
        return head + b"\r\n\r\n" + body
    return head + b"\r\n\r\n(body not included)\r\n"
