import pytest

from dmarc.appsettings import SettingError, get_all, mailbox_config, reset_value, set_value


def test_defaults_come_from_environment(session, settings):
    settings.mailbox_address = "env@example.com"
    cfg = mailbox_config(session, settings)
    assert cfg.address == "env@example.com" and cfg.poll_minutes == 15
    assert (cfg.source_folder, cfg.processed_folder, cfg.failed_folder) == ("Inbox", "Verwerkt", "Fout")
    assert get_all(session, settings)["mailbox.address"]["source"] == "environment"


def test_database_overrides_and_reset(session, settings):
    settings.mailbox_address = "env@example.com"
    set_value(session, "mailbox.address", "  DMARC@Example.com ", user="admin")
    set_value(session, "mailbox.poll_minutes", "30")
    set_value(session, "mailbox.enabled", "nee")
    cfg = mailbox_config(session, settings)
    assert (cfg.address, cfg.poll_minutes, cfg.enabled) == ("dmarc@example.com", 30, False)
    entry = get_all(session, settings)["mailbox.address"]
    assert entry["source"] == "database" and entry["updated_by"] == "admin"
    reset_value(session, "mailbox.address")
    assert mailbox_config(session, settings).address == "env@example.com"


@pytest.mark.parametrize("key,value", [
    ("mailbox.address", "not-an-address"),
    ("mailbox.poll_minutes", 0),
    ("mailbox.poll_minutes", "abc"),
    ("mailbox.batch_size", 5000),
    ("mailbox.processed_folder", "Inbox//x"),
    ("mailbox.enabled", "maybe"),
    ("graph.client_secret", "x"),
])
def test_invalid_values(session, key, value):
    with pytest.raises(SettingError):
        set_value(session, key, value)
