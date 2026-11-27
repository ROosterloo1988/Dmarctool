"""DKIM public key lookup for selectors seen in the reports."""

from __future__ import annotations

import base64
import binascii
from typing import Any

from dmarc.dnscheck.findings import Finding
from dmarc.dnscheck.resolver import DnsLookupError, Resolver, TempError

MIN_BITS = 2048
INSECURE_BITS = 1024


def parse_tags(txt: str) -> dict[str, str]:
    tags = {}
    for part in txt.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags.setdefault(k.strip().lower(), "".join(v.split()))
    return tags


def key_bits(key_type: str, p: str) -> int | None:
    """Key size in bits for an RSA (SubjectPublicKeyInfo or PKCS#1) or Ed25519 key."""
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    try:
        der = base64.b64decode(p, validate=False)
    except (binascii.Error, ValueError):
        return None
    if key_type == "ed25519":
        return 256 if len(der) == 32 else None
    try:
        key = load_der_public_key(der)
    except ValueError:
        # Some publishers put a bare PKCS#1 RSAPublicKey in p= instead of SubjectPublicKeyInfo.
        return _pkcs1_bits(der)
    if isinstance(key, rsa.RSAPublicKey):
        return key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return 256
    return None


def _pkcs1_bits(der: bytes) -> int | None:
    """Minimal DER walk of RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }."""

    def read_len(buf: bytes, i: int) -> tuple[int, int]:
        n = buf[i]
        if n < 0x80:
            return n, i + 1
        k = n & 0x7F
        return int.from_bytes(buf[i + 1 : i + 1 + k], "big"), i + 1 + k

    try:
        if der[0] != 0x30:
            return None
        _, i = read_len(der, 1)
        if der[i] != 0x02:
            return None
        n_len, i = read_len(der, i + 1)
        modulus = int.from_bytes(der[i : i + n_len], "big")
        return modulus.bit_length() or None
    except IndexError:
        return None


def check_selector(domain: str, selector: str, resolver: Resolver) -> tuple[dict[str, Any], list[Finding]]:
    name = f"{selector}._domainkey.{domain}"
    info: dict[str, Any] = {"selector": selector, "name": name}
    findings: list[Finding] = []
    try:
        records = resolver.txt(name)
    except TempError as exc:
        findings.append(Finding("dkim", "warning", "dkim.dns_error", f"DNS lookup of {name} failed: {exc}."))
        return info, findings
    except DnsLookupError:
        info["status"] = "missing"
        findings.append(Finding("dkim", "warning", "dkim.selector_missing",
                                f"DKIM selector '{selector}' appears in the reports, but {name} does not exist (any more).",
                                "If this selector is still in use, publish its key; if it was rotated, this is expected.",
                                {"selector": selector}))
        return info, findings

    records = [r for r in records if "p=" in r.replace(" ", "")]
    if not records:
        info["status"] = "invalid"
        findings.append(Finding("dkim", "error", "dkim.invalid", f"{name} has no DKIM key record (no p= tag).",
                                detail={"selector": selector}))
        return info, findings
    if len(records) > 1:
        findings.append(Finding("dkim", "warning", "dkim.multiple", f"{name} has multiple TXT records; verification may fail.",
                                detail={"selector": selector}))

    tags = parse_tags(records[0])
    info["tags"] = {k: v for k, v in tags.items() if k != "p"}
    k = tags.get("k", "rsa").lower()
    p = tags.get("p", "")
    if not p:
        info["status"] = "revoked"
        findings.append(Finding("dkim", "info", "dkim.revoked", f"Selector '{selector}' is revoked (empty p=).",
                                detail={"selector": selector}))
        return info, findings
    bits = key_bits(k, p)
    info["key_type"], info["bits"] = k, bits
    if bits is None:
        info["status"] = "invalid"
        findings.append(Finding("dkim", "error", "dkim.invalid_key", f"The public key of selector '{selector}' cannot be read.",
                                "Republish the key exactly as your provider supplies it.", {"selector": selector}))
    elif k == "rsa" and bits < INSECURE_BITS:
        info["status"] = "weak"
        findings.append(Finding("dkim", "error", "dkim.insecure_key",
                                f"Selector '{selector}' uses a {bits}-bit RSA key; many receivers reject keys under 1024 bits.",
                                "Generate a new 2048-bit key with your provider and rotate the selector.",
                                {"selector": selector, "bits": bits}))
    elif k == "rsa" and bits < MIN_BITS:
        info["status"] = "weak"
        findings.append(Finding("dkim", "warning", "dkim.weak_key",
                                f"Selector '{selector}' uses a {bits}-bit RSA key (2048 bits recommended).",
                                "Generate a new 2048-bit key with your provider and rotate the selector.",
                                {"selector": selector, "bits": bits}))
    else:
        info["status"] = "ok"
        findings.append(Finding("dkim", "ok", "dkim.ok", f"Selector '{selector}': {bits}-bit {k.upper()} key.",
                                detail={"selector": selector, "bits": bits}))
    if "y" in tags.get("t", "").split(":"):
        findings.append(Finding("dkim", "warning", "dkim.testing",
                                f"Selector '{selector}' is in test mode (t=y); some receivers ignore its signatures.",
                                "Remove t=y once DKIM works.", {"selector": selector}))
    return info, findings
