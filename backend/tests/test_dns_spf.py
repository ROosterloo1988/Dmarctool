import pytest

from dmarc.dnscheck.resolver import FakeResolver
from dmarc.dnscheck.spf import SpfSyntaxError, check_spf, parse_spf


def codes(findings):
    return {f.code for f in findings}


def resolver(record=None, **extra):
    r = FakeResolver()
    if record is not None:
        r.add("example.com", "TXT", record)
    r.add("spf.protection.outlook.com", "TXT", "v=spf1 ip4:40.92.0.0/15 ip4:40.107.0.0/16 ip6:2a01:111:f400::/48 -all")
    r.add("_spf.google.com", "TXT", "v=spf1 include:_netblocks.google.com ~all")
    r.add("_netblocks.google.com", "TXT", "v=spf1 ip4:209.85.128.0/17 ~all")
    r.add("mail.example.com", "A", "192.0.2.25")
    r.add("example.com", "MX", (10, "mx1.example.com"), (20, "mx2.example.com"))
    r.add("mx1.example.com", "A", "198.51.100.1")
    r.add("mx2.example.com", "A", "198.51.100.2")
    r.add("mx2.example.com", "AAAA", "2001:db8::2")
    for (name, typ), vals in extra.get("records", {}).items():
        r.add(name, typ, *vals)
    return r


def test_good_record_and_evaluation():
    a, f = check_spf("example.com", resolver("v=spf1 include:spf.protection.outlook.com include:_spf.google.com a:mail.example.com mx -all"))
    assert a.lookups == 5  # 2 includes + nested google include + a + mx
    assert codes(f) == {"spf.lookups", "spf.fail_all"}
    assert a.evaluate("40.107.22.105") == "pass"
    assert a.evaluate("2a01:111:f400::5") == "pass"
    assert a.evaluate("209.85.220.41") == "pass"
    assert a.evaluate("192.0.2.25") == "pass"
    assert a.evaluate("198.51.100.2") == "pass" and a.evaluate("2001:db8::2") == "pass"
    assert a.evaluate("203.0.113.9") == "fail"
    assert set(a.as_dict()["includes"]) == {"spf.protection.outlook.com", "_spf.google.com", "_netblocks.google.com"}


def test_missing_and_multiple():
    _, f = check_spf("example.com", resolver())
    assert "spf.missing" in codes(f)
    r = resolver("v=spf1 -all")
    r.add("example.com", "TXT", "v=spf1 include:_spf.google.com -all", "some-verification=1")
    a, f = check_spf("example.com", r)
    assert "spf.multiple" in codes(f) and a.evaluate("1.2.3.4") == "permerror"


def test_too_many_lookups():
    recs = {(f"inc{i}.example.net", "TXT"): [f"v=spf1 ip4:192.0.2.{i} -all"] for i in range(11)}
    record = "v=spf1 " + " ".join(f"include:inc{i}.example.net" for i in range(11)) + " -all"
    a, f = check_spf("example.com", resolver(record, records=recs))
    assert a.lookups == 11 and "spf.too_many_lookups" in codes(f)
    assert a.evaluate("192.0.2.1") == "permerror"


def test_near_limit():
    recs = {(f"inc{i}.example.net", "TXT"): ["v=spf1 -all"] for i in range(9)}
    record = "v=spf1 " + " ".join(f"include:inc{i}.example.net" for i in range(9)) + " -all"
    _, f = check_spf("example.com", resolver(record, records=recs))
    assert "spf.near_lookup_limit" in codes(f)


def test_void_lookups_and_include_without_record():
    a, f = check_spf("example.com", resolver("v=spf1 include:gone1.example.net include:gone2.example.net a:gone3.example.net -all"))
    assert a.void_lookups == 3
    assert {"spf.void_lookups", "spf.include_without_record"} <= codes(f)


@pytest.mark.parametrize("all_term,code", [("+all", "spf.plus_all"), ("?all", "spf.neutral_all"),
                                           ("~all", "spf.softfail_all"), ("", "spf.no_all")])
def test_all_qualifiers(all_term, code):
    _, f = check_spf("example.com", resolver(f"v=spf1 ip4:192.0.2.1 {all_term}".strip()))
    assert code in codes(f)


def test_redirect_follows_all():
    r = resolver("v=spf1 redirect=_spf.example.net", records={("_spf.example.net", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"]})
    a, f = check_spf("example.com", r)
    assert "spf.fail_all" in codes(f) and a.evaluate("192.0.2.7") == "pass" and a.evaluate("192.0.3.7") == "fail"


def test_ptr_and_exists_are_unresolvable():
    a, f = check_spf("example.com", resolver("v=spf1 ptr exists:%{i}.bl.example.net -all"))
    assert "spf.ptr" in codes(f) and a.evaluate("192.0.2.1") == "unknown"


def test_loop_detection():
    r = resolver("v=spf1 include:a.example.net -all", records={
        ("a.example.net", "TXT"): ["v=spf1 include:b.example.net -all"],
        ("b.example.net", "TXT"): ["v=spf1 include:a.example.net -all"]})
    _, f = check_spf("example.com", r)
    assert "spf.loop" in codes(f)


@pytest.mark.parametrize("rec", ["v=spf2 -all", "v=spf1 ip4:300.1.1.1 -all", "v=spf1 ip4:2001:db8::1 -all",
                                 "v=spf1 foo:bar -all", "v=spf1 include -all", "v=spf1 redirect=a redirect=b",
                                 "v=spf1 a/40 -all", "v=spf1 all:x"])
def test_syntax_errors(rec):
    with pytest.raises(SpfSyntaxError):
        parse_spf(rec)


def test_syntax_error_reported():
    _, f = check_spf("example.com", resolver("v=spf1 inlcude:_spf.google.com -all"))
    assert "spf.syntax" in codes(f)


def test_cidr_on_a_and_mx():
    terms = parse_spf("v=spf1 a/24 mx:example.org/28//64 -all")
    assert (terms[0].v4, terms[1].value, terms[1].v4, terms[1].v6) == (24, "example.org", 28, 64)
    a, _ = check_spf("example.com", resolver("v=spf1 a:mail.example.com/24 -all"))
    assert a.evaluate("192.0.2.200") == "pass"
