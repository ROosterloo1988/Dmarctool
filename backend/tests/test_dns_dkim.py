import base64
import random

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from dmarc.dnscheck.dkim import check_selector, key_bits
from dmarc.dnscheck.resolver import FakeResolver


def rsa_p(bits, pkcs1=False):
    if bits < 1024:  # cryptography refuses to generate these; build a public key with a random modulus
        key = rsa.RSAPublicNumbers(65537, random.getrandbits(bits) | (1 << (bits - 1)) | 1).public_key()
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key()
    fmt = serialization.PublicFormat.PKCS1 if pkcs1 else serialization.PublicFormat.SubjectPublicKeyInfo
    return base64.b64encode(key.public_bytes(serialization.Encoding.DER, fmt)).decode()


def test_key_bits():
    assert key_bits("rsa", rsa_p(2048)) == 2048
    assert key_bits("rsa", rsa_p(1024, pkcs1=True)) == 1024
    ed = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert key_bits("ed25519", base64.b64encode(ed).decode()) == 256
    assert key_bits("rsa", "bm90LWEta2V5") is None


@pytest.mark.parametrize("bits,code,severity", [(2048, "dkim.ok", "ok"), (1024, "dkim.weak_key", "warning"),
                                                (768, "dkim.insecure_key", "error")])
def test_selector_key_strength(bits, code, severity):
    p = rsa_p(bits)
    # Long keys are split in several strings with spaces; parse_tags must cope.
    r = FakeResolver().add("s1._domainkey.example.com", "TXT", f"v=DKIM1; k=rsa; p={p[:100]} {p[100:]}")
    info, f = check_selector("example.com", "s1", r)
    assert info["bits"] == bits and [(x.code, x.severity) for x in f] == [(code, severity)]


def test_missing_revoked_testing():
    r = FakeResolver()
    _, f = check_selector("example.com", "old", r)
    assert f[0].code == "dkim.selector_missing"
    r.add("rev._domainkey.example.com", "TXT", "v=DKIM1; p=")
    info, f = check_selector("example.com", "rev", r)
    assert info["status"] == "revoked" and f[0].code == "dkim.revoked"
    r.add("t._domainkey.example.com", "TXT", f"v=DKIM1; t=y; p={rsa_p(2048)}")
    _, f = check_selector("example.com", "t", r)
    assert {x.code for x in f} == {"dkim.ok", "dkim.testing"}
