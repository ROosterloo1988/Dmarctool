import email

from dmarc.forensic_analysis import (
    analyse, anonymised_eml, defang, parse_authentication_results, parse_dkim_signature, parse_received,
)
from dmarc.parsing.ruf import parse_forensic
from tests.conftest import fixture_bytes


def phishing():
    r = parse_forensic(email.message_from_bytes(fixture_bytes("ruf", "arf_phishing.eml")), store_body=True)
    return r, [list(h) for h in r.original_headers]


def test_authentication_results():
    a = parse_authentication_results("mx.example 1; spf=pass (sender ok) smtp.mailfrom=a.example; "
                                     "dkim=fail header.d=b.example header.s=s1; dmarc=fail header.from=c.example")
    assert a["authserv_id"] == "mx.example"
    assert [(r["method"], r["result"]) for r in a["results"]] == [("spf", "pass"), ("dkim", "fail"), ("dmarc", "fail")]
    assert a["results"][1]["props"] == {"header.d": "b.example", "header.s": "s1"}
    assert parse_authentication_results(None) == {"authserv_id": None, "results": []}


def test_dkim_signature():
    assert parse_dkim_signature("v=1; a=rsa-sha256; d=x.example; s=k1; b=AAAA BBBB; bh=xyz") == {
        "v": "1", "a": "rsa-sha256", "d": "x.example", "s": "k1"}


def test_received_chain_oldest_first():
    hops = parse_received([
        "from mx.r.example (mx.r.example [198.51.100.5]) by store.r.example with LMTP; Mon, 24 Nov 2025 11:02:05 +0000",
        "from out.s.example (out.s.example [IPv6:2001:db8::7]) by mx.r.example with ESMTPS; Mon, 24 Nov 2025 11:02:03 +0000",
    ])
    assert [h["ip"] for h in hops] == ["2001:db8::7", "198.51.100.5"]
    assert hops[0]["by"] == "mx.r.example" and hops[0]["with"] == "ESMTPS"


def test_full_analysis_of_phishing_report():
    r, headers = phishing()
    a = analyse(headers, r.original_body, r.authentication_results, r.reported_domain)
    assert a["auth_summary"] == {"dmarc": "fail", "spf": "fail", "dkim": "pass"}
    assert a["dkim_signatures"][0]["d"] == "bulk-sender.example"
    assert [h["ip"] for h in a["hops"]] == ["10.1.2.3", "203.0.113.66", "198.51.100.5"]
    assert a["hops"][0]["helo"] == "workstation"
    codes = {x["code"] for x in a["anomalies"]}
    assert {"reply_to_foreign", "display_name_spoof", "message_id_foreign", "mailer", "foreign_links"} <= codes
    body = a["body"]
    assert body["link_domains"] == {"pay.collect-invoices.example": 1, "www.example.com": 1}
    assert body["urls"][0]["url"] == "hxxps://pay[.]collect-invoices.example/inv?id=1187"  # defanged, never clickable
    [att] = body["attachments"]
    assert att["filename"] == "invoice-2025-1187.pdf" and att["content_type"] == "application/pdf" and len(att["sha256"]) == 64
    assert "please pay invoice" in body["text"] and "<script>" not in body["text"]


def test_html_only_body_is_converted_to_text():
    headers = [["Content-Type", "text/html; charset=utf-8"]]
    body = b"<html><style>p{}</style><body><p>Hello &amp; <b>welcome</b></p><script>bad()</script></body></html>"
    b = analyse(headers, body, None, "example.com")["body"]
    assert "Hello & welcome" in " ".join(b["text"].split()) and "bad()" not in b["text"]


def test_no_body():
    r, headers = phishing()
    assert analyse(headers, None, None, "example.com")["body"] is None


def test_defang():
    assert defang("https://evil.example/x") == "hxxps://evil[.]example/x"


def test_anonymised_export():
    r, headers = phishing()
    eml = anonymised_eml(headers, r.original_body, include_body=False).decode()
    assert "j.jansen@receiver.example" not in eml
    assert "To: \"Jan Jansen\" <redacted@receiver.example>" in eml
    assert "for <redacted>" in eml and "Reply-To: payments@collect-invoices.example" in eml
    assert "(body not included)" in eml and "X-DMARC-Portal-Note" in eml
    with_body = anonymised_eml(headers, r.original_body, include_body=True)
    assert b"invoice-2025-1187.pdf" in with_body
    # The export parses as a normal e-mail again.
    assert email.message_from_bytes(with_body)["Subject"] == "Outstanding invoice 2025-1187"
