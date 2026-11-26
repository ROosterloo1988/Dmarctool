"""ASN / country lookups from local MaxMind-format databases (DB-IP Lite or GeoLite2).

DB-IP Lite is licensed CC BY 4.0: the UI must show "IP data by DB-IP" with a link to
https://db-ip.com.
"""

from __future__ import annotations

import gzip
import io
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import maxminddb

from dmarc.config import Settings, get_settings

log = logging.getLogger(__name__)

DBIP_URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz"
FILES = {"asn": "dbip-asn-lite.mmdb", "country": "dbip-country-lite.mmdb"}


@dataclass
class GeoResult:
    asn: int | None = None
    as_org: str | None = None
    country: str | None = None


class GeoIp:
    def __init__(self, asn_path: str | None, country_path: str | None):
        self._asn = _open(asn_path)
        self._country = _open(country_path)

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> GeoIp:
        s = settings or get_settings()
        return cls(s.geoip_asn_path or str(Path(s.geoip_dir) / FILES["asn"]),
                   s.geoip_country_path or str(Path(s.geoip_dir) / FILES["country"]))

    @property
    def available(self) -> bool:
        return self._asn is not None

    def lookup(self, ip: str) -> GeoResult:
        r = GeoResult()
        if self._asn is not None:
            rec = self._asn.get(ip) or {}
            r.asn = rec.get("autonomous_system_number")
            r.as_org = rec.get("autonomous_system_organization")
        if self._country is not None:
            rec = self._country.get(ip) or {}
            r.country = (rec.get("country") or {}).get("iso_code")
        return r

    def close(self) -> None:
        for db in (self._asn, self._country):
            if db is not None:
                db.close()


def _open(path: str | None):
    if not path or not Path(path).exists():
        return None
    try:
        return maxminddb.open_database(path)
    except (maxminddb.InvalidDatabaseError, OSError, ValueError) as exc:
        log.error("cannot open GeoIP database %s: %s", path, exc)
        return None


def needs_update(settings: Settings | None = None, now: datetime | None = None) -> bool:
    s = settings or get_settings()
    now = now or datetime.now(UTC)
    for name in FILES.values():
        p = Path(s.geoip_dir) / name
        if not p.exists() or datetime.fromtimestamp(p.stat().st_mtime, UTC) < now - timedelta(days=30):
            return True
    return False


def download_dbip(settings: Settings | None = None, http: httpx.Client | None = None,
                  now: datetime | None = None) -> dict[str, str]:
    """Download the current (or previous) month's DB-IP Lite ASN + country databases."""
    s = settings or get_settings()
    now = now or datetime.now(UTC)
    client = http or httpx.Client(timeout=120, follow_redirects=True)
    dest_dir = Path(s.geoip_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    months = [now.strftime("%Y-%m"), (now.replace(day=1) - timedelta(days=1)).strftime("%Y-%m")]
    result = {}
    try:
        for kind, filename in FILES.items():
            for month in months:
                url = DBIP_URL.format(kind=kind, month=month)
                resp = client.get(url)
                if resp.status_code == 404:
                    continue
                resp.raise_for_status()
                fd, tmp = tempfile.mkstemp(dir=dest_dir, suffix=".tmp")
                try:
                    with os.fdopen(fd, "wb") as out, gzip.GzipFile(fileobj=io.BytesIO(resp.content)) as gz:
                        shutil.copyfileobj(gz, out)
                    maxminddb.open_database(tmp).close()  # validate before replacing
                    os.replace(tmp, dest_dir / filename)
                finally:
                    if os.path.exists(tmp):
                        os.unlink(tmp)
                result[kind] = month
                break
            else:
                raise RuntimeError(f"no DB-IP {kind} database found for {months}")
    finally:
        if http is None:
            client.close()
    return result

