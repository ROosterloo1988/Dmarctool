from dmarc.senders import load_catalog


def test_builtin_catalog_loads():
    c = load_catalog()
    assert {"microsoft365", "google_workspace", "flowmailer", "mailchimp", "sendgrid", "amazon_ses"} <= set(c.senders)
    assert all(s.name and s.dkim_setup for s in c.senders.values())


def test_identify():
    c = load_catalog()
    assert c.by_ptr("mail-eopbgr80105.outbound.protection.outlook.com").key == "microsoft365"
    assert c.by_ptr("o1.ptr1234.mailer.flowmailer.net").key == "flowmailer"
    assert c.by_ptr("evilflowmailer.net") is None  # label boundary
    assert c.by_domains(["s1.mcsv.net"], []).key == "mailchimp"
    assert c.by_domains([], ["bounces.sendgrid.net"]).key == "sendgrid"
    assert c.by_asn(15169).key == "google_workspace"
    assert c.identify(None, 8075) is None  # Azure shares AS8075: no guess from ASN alone


def test_override_catalog(tmp_path):
    p = tmp_path / "local.yaml"
    p.write_text("crm_tool:\n  name: Our CRM\n  ptr_suffixes: [crm.example.net]\n  spf_include: spf.crm.example.net\n")
    load_catalog.cache_clear()
    try:
        c = load_catalog(str(p))
        assert c.by_ptr("out1.crm.example.net").name == "Our CRM" and "sendgrid" in c.senders
    finally:
        load_catalog.cache_clear()
