"""Thin DNS resolver abstraction so checks can be tested without network access."""

from __future__ import annotations

import ipaddress
from typing import Protocol

import dns.exception
import dns.name
import dns.resolver
import dns.reversename


class DnsLookupError(Exception):
    """Base class for lookup failures."""


class NxDomain(DnsLookupError):
    """The name does not exist (counts as a 'void lookup' for SPF)."""


class NoData(DnsLookupError):
    """The name exists but has no records of this type (also a 'void lookup')."""


class TempError(DnsLookupError):
    """Timeout / SERVFAIL: result unknown, try again later."""


class Resolver(Protocol):
    def txt(self, name: str) -> list[str]: ...
    def a(self, name: str) -> list[str]: ...
    def aaaa(self, name: str) -> list[str]: ...
    def mx(self, name: str) -> list[tuple[int, str]]: ...
    def ptr(self, ip: str) -> list[str]: ...


class DnsPythonResolver:
    def __init__(self, nameservers: list[str] | None = None, timeout: float = 5.0):
        self._r = dns.resolver.Resolver()
        if nameservers:
            self._r.nameservers = nameservers
        self._r.lifetime = timeout
        self._cache: dict[tuple[str, str], object] = {}

    def _query(self, name: str, rdtype: str):
        key = (name.lower().rstrip("."), rdtype)
        if key in self._cache:
            cached = self._cache[key]
            if isinstance(cached, DnsLookupError):
                raise cached
            return cached
        try:
            answer = list(self._r.resolve(name, rdtype, raise_on_no_answer=True))
        except dns.resolver.NXDOMAIN:
            err: DnsLookupError = NxDomain(f"{name}: NXDOMAIN")
        except dns.resolver.NoAnswer:
            err = NoData(f"{name}: no {rdtype} records")
        except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.LifetimeTimeout) as exc:
            raise TempError(f"{name} {rdtype}: {exc}") from exc
        except (dns.name.LabelTooLong, dns.name.EmptyLabel, dns.name.NameTooLong) as exc:
            err = NxDomain(f"{name}: invalid name ({exc})")
        else:
            self._cache[key] = answer
            return answer
        self._cache[key] = err
        raise err

    def txt(self, name: str) -> list[str]:
        out = []
        for rr in self._query(name, "TXT"):
            out.append(b"".join(rr.strings).decode("utf-8", errors="replace"))
        return out

    def a(self, name: str) -> list[str]:
        return [rr.address for rr in self._query(name, "A")]

    def aaaa(self, name: str) -> list[str]:
        return [rr.address for rr in self._query(name, "AAAA")]

    def mx(self, name: str) -> list[tuple[int, str]]:
        return [(rr.preference, rr.exchange.to_text(omit_final_dot=True).lower()) for rr in self._query(name, "MX")]

    def ptr(self, ip: str) -> list[str]:
        rev = dns.reversename.from_address(str(ipaddress.ip_address(ip))).to_text()
        return [rr.target.to_text(omit_final_dot=True).lower() for rr in self._query(rev, "PTR")]


class FakeResolver:
    """Dict-based resolver for tests: {('name', 'TXT'): [...], ...}; missing name -> NXDOMAIN."""

    def __init__(self, records: dict[tuple[str, str], list] | None = None, temp_errors: set[str] | None = None):
        self.records = {(k[0].lower().rstrip("."), k[1].upper()): v for k, v in (records or {}).items()}
        self.temp_errors = temp_errors or set()
        self.queries: list[tuple[str, str]] = []

    def add(self, name: str, rdtype: str, *values) -> FakeResolver:
        self.records.setdefault((name.lower().rstrip("."), rdtype.upper()), []).extend(values)
        return self

    def _get(self, name: str, rdtype: str) -> list:
        name = name.lower().rstrip(".")
        self.queries.append((name, rdtype))
        if name in self.temp_errors:
            raise TempError(f"{name}: timeout")
        if (name, rdtype) in self.records:
            vals = self.records[(name, rdtype)]
            if not vals:
                raise NoData(f"{name}: no {rdtype}")
            return list(vals)
        if any(k[0] == name for k in self.records):
            raise NoData(f"{name}: no {rdtype}")
        raise NxDomain(f"{name}: NXDOMAIN")

    def txt(self, name):
        return self._get(name, "TXT")

    def a(self, name):
        return self._get(name, "A")

    def aaaa(self, name):
        return self._get(name, "AAAA")

    def mx(self, name):
        return self._get(name, "MX")

    def ptr(self, ip):
        return self._get(dns.reversename.from_address(ip).to_text(), "PTR")
