"""Application settings, read from environment variables (prefix ``DMARC_``)."""

from functools import lru_cache

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


@lru_cache
def get_settings() -> Settings:
    return Settings()
