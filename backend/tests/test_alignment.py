import pytest

from dmarc.parsing.alignment import is_aligned, normalize_domain, organizational_domain


@pytest.mark.parametrize("domain,org", [
    ("example.com", "example.com"),
    ("mail.news.example.com", "example.com"),
    ("shop.example.co.uk", "example.co.uk"),
    ("EXAMPLE.NL.", "example.nl"),
    ("user@bounces.example.com", "example.com"),
])
def test_organizational_domain(domain, org):
    assert organizational_domain(domain) == org


@pytest.mark.parametrize("auth,frm,mode,expected", [
    ("example.com", "example.com", "r", True),
    ("bounce.example.com", "example.com", "r", True),
    ("bounce.example.com", "example.com", "s", False),
    ("example.com", "example.com", "s", True),
    ("esp-example.net", "example.com", "r", False),
    ("a.example.co.uk", "b.example.co.uk", "r", True),
    ("example.co.uk", "other.co.uk", "r", False),
    (None, "example.com", "r", False),
    ("example.com", None, "r", False),
])
def test_is_aligned(auth, frm, mode, expected):
    assert is_aligned(auth, frm, mode) is expected


def test_normalize_idn():
    assert normalize_domain("bücher.example") == "xn--bcher-kva.example"
    assert normalize_domain("  <Mail.Example.COM>  ") == "mail.example.com"
    assert normalize_domain("") is None
