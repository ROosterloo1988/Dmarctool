import pytest

from dmarc.dnscheck.dmarc_record import check_dmarc
from dmarc.dnscheck.resolver import FakeResolver


def codes(findings):
    return {f.code for f in findings}


def run(records, extra=None, domain="example.com", temp=None):
    r = FakeResolver(temp_errors=temp)
    for rec in records:
        r.add(f"_dmarc.{domain}", "TXT", rec)
    for (name, typ), vals in (extra or {}).items():
        r.add(name, typ, *vals)
    return check_dmarc(domain, r)


def test_valid_reject():
    res, f = run(["v=DMARC1; p=reject; rua=mailto:dmarc@example.com; adkim=s"])
    assert res["effective_policy"] == "reject" and res["rua"] == ["dmarc@example.com"]
    assert codes(f) == {"dmarc.p_reject"}


def test_missing():
    _, f = run([])
    assert "dmarc.missing" in codes(f)


def test_non_dmarc_txt_ignored():
    _, f = run(["google-site-verification=abc", "v=DMARC1; p=none; rua=mailto:d@example.com"])
    assert "dmarc.multiple" not in codes(f) and "dmarc.p_none" in codes(f)


def test_multiple_records():
    res, f = run(["v=DMARC1; p=none", "v=DMARC1; p=reject"])
    [m] = [x for x in f if x.code == "dmarc.multiple"]
    assert m.severity == "error" and "ignore" in m.message and len(m.detail["records"]) == 2


@pytest.mark.parametrize("rec,code", [
    ("v=DMARC1; p=block", "dmarc.invalid_value"),
    ("v=DMARC1; p=none; pct=150", "dmarc.invalid_value"),
    ("v=DMARC1; p=none; adkim=x", "dmarc.invalid_value"),
    ("v=DMARC1; p=none; fo=2", "dmarc.invalid_value"),
    ("v=DMARC1; p=none; rua=dmarc@example.com", "dmarc.invalid_uri"),
    ("v=DMARC1; p=none; rue=mailto:x@example.com", "dmarc.unknown_tag"),
    ("v=DMARC1; p=none; garbage", "dmarc.syntax"),
    ("v=DMARC1; rua=mailto:x@example.com", "dmarc.p_missing"),
    ("v=DMARC1; p=none", "dmarc.no_rua"),
    ("v=DMARC1; p=quarantine; pct=25; rua=mailto:d@example.com", "dmarc.pct_partial"),
    ("v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com", "dmarc.sp_weaker"),
    ("v=DMARC1; p=none; rua=mailto:d@example.com; ruf=mailto:d@example.com", "dmarc.ruf_fo"),
])
def test_problems(rec, code):
    _, f = run([rec])
    assert code in codes(f)


def test_dmarcbis_tags_accepted():
    _, f = run(["v=DMARC1; p=reject; np=reject; t=n; psd=n; rua=mailto:d@example.com"])
    assert "dmarc.unknown_tag" not in codes(f)


def test_external_destination_verification():
    rec = "v=DMARC1; p=none; rua=mailto:reports@vendor.example,mailto:dmarc@example.com!10m; ruf=mailto:f@other.example"
    res, f = run([rec], {("example.com._report._dmarc.vendor.example", "TXT"): ["v=DMARC1"]})
    assert res["external_destinations"] == {"vendor.example": True, "other.example": False}
    [e] = [x for x in f if x.code == "dmarc.external_unverified"]
    assert e.detail["record_name"] == "example.com._report._dmarc.other.example"
    assert res["rua"] == ["reports@vendor.example", "dmarc@example.com"]


def test_subdomain_inherits_org_policy():
    r = FakeResolver().add("_dmarc.example.com", "TXT", "v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.com")
    res, f = check_dmarc("mail.example.com", r)
    assert res["inherited"] and res["effective_policy"] == "quarantine"
    assert "dmarc.inherited" in codes(f)


def test_temp_error():
    _, f = run([], temp={"_dmarc.example.com"})
    assert codes(f) == {"dmarc.dns_error"}


def test_ruf_with_fo1_no_hint():
    _, f = run(["v=DMARC1; p=none; rua=mailto:d@example.com; ruf=mailto:d@example.com; fo=1"])
    assert "dmarc.ruf_fo" not in codes(f)
