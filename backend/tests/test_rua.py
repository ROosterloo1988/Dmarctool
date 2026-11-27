from datetime import UTC, datetime

import pytest

from dmarc.parsing.rua import ReportParseError, parse_aggregate
from tests.conftest import fixture_bytes


def rec_by_ip(report, ip):
    return next(r for r in report.records if r.source_ip == ip)


def test_google():
    r = parse_aggregate(fixture_bytes("src", "google.xml"))
    assert (r.org_name, r.report_id, r.domain) == ("google.com", "13190401177745345981", "example.com")
    assert r.email == "noreply-dmarc-support@google.com"
    assert r.date_begin == datetime(2025, 11, 24, tzinfo=UTC)
    assert r.policy.p == "none" and r.policy.pct == 100 and r.policy.np == "none"
    assert len(r.records) == 3 and r.message_count == 1615

    m365 = rec_by_ip(r, "2a01:111:f403:c201::1")
    assert m365.count == 412 and m365.dmarc_pass and m365.dkim_aligned and m365.spf_aligned
    assert m365.dkim[0].selector == "selector1"
    assert m365.envelope_from is None  # Google does not report envelope_from

    esp = rec_by_ip(r, "198.51.100.23")
    # Both SPF and DKIM pass, but for the ESP's own domain: not aligned -> DMARC fail.
    assert esp.dkim[0].result == "pass" and esp.spf[0].result == "pass"
    assert not esp.dkim_aligned and not esp.spf_aligned and not esp.dmarc_pass

    spoof = rec_by_ip(r, "203.0.113.77")
    assert spoof.spf[0].result == "softfail" and not spoof.dkim and not spoof.dmarc_pass


def test_microsoft():
    r = parse_aggregate(fixture_bytes("src", "microsoft.xml"))
    assert r.org_name == "Enterprise Outlook" and r.version == "1.0" and r.policy.fo == "1"
    rec = rec_by_ip(r, "40.107.22.105")
    assert rec.envelope_to == "contoso.example" and rec.envelope_from == "example.com"
    assert rec.spf[0].scope == "mfrom" and rec.dmarc_pass
    news = rec_by_ip(r, "192.0.2.10")
    # Relaxed SPF alignment: news.example.com aligns with example.com
    assert news.spf_aligned and not news.dkim_aligned and news.dmarc_pass


def test_yahoo_reason_and_forwarding():
    r = parse_aggregate(fixture_bytes("src", "yahoo.xml"))
    [rec] = r.records
    assert rec.reasons == [{"type": "forwarded", "comment": "mailing list"}]
    assert rec.dkim_aligned and not rec.spf_aligned and rec.dmarc_pass


def test_mailru_whitespace_and_case():
    r = parse_aggregate(fixture_bytes("src", "mailru.xml"))
    assert r.domain == "example.com"
    [rec] = r.records
    assert rec.source_ip == "203.0.113.5" and rec.header_from == "example.com"
    assert rec.dkim[0].selector is None and not rec.dmarc_pass


def test_dmarcbis_namespace_and_strict_dkim():
    r = parse_aggregate(fixture_bytes("src", "dmarcbis.xml"))
    assert r.generator == "ExampleMTA 4.2"
    p = r.policy
    assert (p.p, p.sp, p.np, p.adkim, p.aspf, p.testing, p.pct) == ("quarantine", "quarantine", "reject", "s", "r", "n", None)
    [rec] = r.records
    assert rec.source_ip == "2001:db8::25" and rec.disposition == "quarantine"
    assert not rec.dkim_aligned  # adkim=s: mail.example.com != example.com
    assert rec.spf_aligned and rec.dmarc_pass  # aspf=r


def test_quirky_reporter():
    r = parse_aggregate(fixture_bytes("src", "quirky.xml"))  # wrong encoding declaration
    assert r.report_id == "q-7781" and r.domain == "example.com"
    assert r.date_begin == datetime(2025, 11, 24, tzinfo=UTC)
    [rec] = r.records
    assert rec.source_ip == "192.0.2.200"  # ::ffff: mapped address normalised
    assert rec.count == 7
    assert rec.header_from == "example.com"  # missing header_from falls back to policy domain
    assert not rec.spf_aligned  # HELO-scoped pass never counts for DMARC


def test_wrapped_root_and_no_auth_results():
    xml = b"""<reports><feedback><report_metadata><org_name>x</org_name><report_id>1</report_id>
    <date_range><begin>0</begin><end>86400</end></date_range></report_metadata>
    <policy_published><domain>example.com</domain></policy_published>
    <record><row><source_ip>192.0.2.1</source_ip><count>4</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers></record></feedback></reports>"""
    r = parse_aggregate(xml)
    [rec] = r.records
    # No auth_results: fall back to the reporter's own evaluation.
    assert rec.dkim_aligned and not rec.spf_aligned and rec.dmarc_pass
    assert r.policy.adkim == "r" and r.policy.p is None


def test_report_without_records():
    xml = fixture_bytes("src", "yahoo.xml")
    start, end = xml.index(b"<record>"), xml.index(b"</record>") + len(b"</record>")
    r = parse_aggregate(xml[:start] + xml[end:])
    assert r.records == [] and r.message_count == 0


@pytest.mark.parametrize("name,msg", [
    ("truncated.xml", "invalid XML"),
    ("missing_report_id.xml", "missing report_id"),
    ("wrong_root.xml", "expected <feedback>"),
    ("xxe.xml", "unsafe XML"),
    ("billion_laughs.xml", "unsafe XML"),
])
def test_broken(name, msg):
    with pytest.raises(ReportParseError, match=msg):
        parse_aggregate(fixture_bytes("broken", name))


def test_invalid_source_ip():
    xml = fixture_bytes("src", "yahoo.xml").replace(b"209.85.220.41", b"not-an-ip")
    with pytest.raises(ReportParseError, match="source_ip"):
        parse_aggregate(xml)
