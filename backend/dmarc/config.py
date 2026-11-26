"""Application settings, read from environment variables (prefix ``DMARC_``)."""

from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DMARC_", env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://dmarc:dmarc@localhost:5432/dmarc"

    # --- Archive / payload safety limits -------------------------------------------------
    max_message_bytes: int = 50 * 1024 * 1024  # raw e-mail size we are willing to handle
    max_attachment_bytes: int = 25 * 1024 * 1024  # compressed attachment size
    max_uncompressed_bytes: int = 100 * 1024 * 1024  # per extracted file
    max_total_uncompressed_bytes: int = 200 * 1024 * 1024  # all files of one attachment
    max_archive_members: int = 50
    max_compression_ratio: int = 200  # uncompressed / compressed, zip-bomb heuristic
    max_nesting_depth: int = 2  # e.g. zip containing a .gz

    # --- Forensic (RUF) privacy ----------------------------------------------------------
    ruf_store_body: bool = False
    ruf_retention_days: int = 30

    # --- Aggregate (RUA) retention -------------------------------------------------------
    rua_store_raw_xml: bool = True
    rua_retention_days: int = 730

    # --- Microsoft Graph (secrets: environment only, never in the database) --------------
    graph_tenant_id: str | None = None
    graph_client_id: str | None = None
    graph_client_secret: SecretStr | None = None
    graph_certificate_path: str | None = None  # PEM file with private key + certificate
    graph_certificate_password: SecretStr | None = None
    graph_authority_host: str = "https://login.microsoftonline.com"
    graph_base_url: str = "https://graph.microsoft.com/v1.0"
    graph_timeout_seconds: float = 60.0

    # --- Mailbox defaults (can be overridden in the management UI / `dmarc settings`) ----
    mailbox_address: str | None = None
    mailbox_source_folder: str = "Inbox"
    mailbox_processed_folder: str = "Verwerkt"
    mailbox_failed_folder: str = "Fout"
    mailbox_poll_minutes: int = 15
    mailbox_batch_size: int = 200
    mailbox_enabled: bool = True

    # --- DNS checks / enrichment -------------------------------------------------------
    dns_nameservers: list[str] = []  # empty: system resolver
    dns_timeout_seconds: float = 5.0
    dns_check_minutes: int = 60
    enrich_minutes: int = 15
    ip_info_max_age_days: int = 30
    geoip_dir: str = "/data/geoip"
    geoip_asn_path: str | None = None  # override, e.g. a MaxMind GeoLite2-ASN.mmdb
    geoip_country_path: str | None = None
    geoip_auto_download: bool = True  # DB-IP Lite (CC BY 4.0), monthly
    senders_catalog_path: str | None = None  # extra/overriding sender definitions (YAML)

    # --- Analysis thresholds -------------------------------------------------------------
    analysis_days: int = 30
    reject_ready_pass_rate: float = 98.0  # % of legitimate mail that must pass DMARC
    significant_messages: int = 10  # minimum failing messages before a source is reported
    min_report_days: int = 14

    # --- Web UI / authentication -------------------------------------------------------
    secret_key: SecretStr | None = None  # signs session cookies; required for the API
    public_url: str = "https://dmarcportal.tenazenergy.com"
    session_hours: int = 8
    cookie_secure: bool = True  # set false only for local http testing
    oidc_tenant_id: str | None = None  # defaults to graph_tenant_id
    oidc_client_id: str | None = None
    oidc_client_secret: SecretStr | None = None
    oidc_admin_role: str = "DMARC.Admin"
    oidc_viewer_role: str = "DMARC.Viewer"
    local_login_enabled: bool = False  # break-glass local accounts (create with `dmarc user add`)
    login_max_failures: int = 5
    login_lockout_minutes: int = 15
    static_dir: str | None = None  # built frontend; default: dmarc/static

    # --- Notifications (defaults; editable in the UI under Settings > Notifications) -----
    notify_enabled: bool = True
    notify_recipients: list[str] = []
    notify_digest_hour_utc: int = 6
    notify_new_source_min_messages: int = 50
    notify_pass_drop_points: float = 5.0
    notify_minutes: int = 15

    # --- Worker --------------------------------------------------------------------------
    worker_tick_seconds: int = 30
    purge_hour_utc: int = 3


@lru_cache
def get_settings() -> Settings:
    return Settings()
