"""Recognition of well-known senders (see senders.yaml)."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from dmarc.config import get_settings
from dmarc.parsing.alignment import organizational_domain

BUILTIN = Path(__file__).with_name("senders.yaml")


@dataclass(frozen=True)
class Sender:
    key: str
    name: str
    category: str = "other"
    ptr_suffixes: tuple[str, ...] = ()
    dkim_domains: tuple[str, ...] = ()
    envelope_domains: tuple[str, ...] = ()
    asns: tuple[int, ...] = ()
    spf_include: str | None = None
    spf_alignable: bool = True
    dkim_setup: str | None = None
    return_path_setup: str | None = None


@dataclass
class Catalog:
    senders: dict[str, Sender] = field(default_factory=dict)

    def get(self, key: str | None) -> Sender | None:
        return self.senders.get(key) if key else None

    def by_ptr(self, ptr: str | None) -> Sender | None:
        if not ptr:
            return None
        host = ptr.lower().rstrip(".")
        for s in self.senders.values():
            if any(host == suf or host.endswith("." + suf) for suf in s.ptr_suffixes):
                return s
        return None

    def by_asn(self, asn: int | None) -> Sender | None:
        if asn is None:
            return None
        return next((s for s in self.senders.values() if asn in s.asns), None)

    def by_domains(self, dkim_domains: Iterable[str | None], envelope_domains: Iterable[str | None]) -> Sender | None:
        dk = {organizational_domain(d) for d in dkim_domains if d}
        env = {organizational_domain(d) for d in envelope_domains if d}
        for s in self.senders.values():
            if dk & set(s.dkim_domains) or env & set(s.envelope_domains):
                return s
        return None

    def identify(self, ptr: str | None, asn: int | None, dkim_domains: Iterable[str | None] = (),
                 envelope_domains: Iterable[str | None] = ()) -> Sender | None:
        return self.by_ptr(ptr) or self.by_domains(dkim_domains, envelope_domains) or self.by_asn(asn)


def _load(path: Path) -> dict[str, Sender]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out = {}
    for key, v in data.items():
        v = v or {}
        out[key] = Sender(
            key=key,
            name=v.get("name", key),
            category=v.get("category", "other"),
            ptr_suffixes=tuple(x.lower() for x in v.get("ptr_suffixes") or ()),
            dkim_domains=tuple(x.lower() for x in v.get("dkim_domains") or ()),
            envelope_domains=tuple(x.lower() for x in v.get("envelope_domains") or ()),
            asns=tuple(int(x) for x in v.get("asns") or ()),
            spf_include=v.get("spf_include"),
            spf_alignable=bool(v.get("spf_alignable", True)),
            dkim_setup=v.get("dkim_setup"),
            return_path_setup=v.get("return_path_setup"),
        )
    return out


@lru_cache
def load_catalog(extra_path: str | None = None) -> Catalog:
    senders = _load(BUILTIN)
    extra = extra_path or get_settings().senders_catalog_path
    if extra and Path(extra).exists():
        senders.update(_load(Path(extra)))
    return Catalog(senders)
