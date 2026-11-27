"""DMARC identifier alignment (RFC 7489 section 3.1).

The organizational domain is determined with the bundled Public Suffix List, so no
network access is needed at runtime.
"""

from __future__ import annotations

from functools import lru_cache

from publicsuffixlist import PublicSuffixList

_psl = PublicSuffixList()


def normalize_domain(domain: str | None) -> str | None:
    if not domain:
        return None
    d = domain.strip().strip(".").lower()
    # Some reporters put a full address in envelope_from / spf domain.
    if "@" in d:
        d = d.rsplit("@", 1)[1]
    d = d.strip("<>").strip()
    if not d:
        return None
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return d


@lru_cache(maxsize=4096)
def organizational_domain(domain: str) -> str:
    d = normalize_domain(domain) or ""
    org = _psl.privatesuffix(d)
    return org or d


def is_aligned(auth_domain: str | None, from_domain: str | None, mode: str | None = "r") -> bool:
    """True if ``auth_domain`` aligns with ``from_domain`` in relaxed ('r') or strict ('s') mode."""
    a = normalize_domain(auth_domain)
    f = normalize_domain(from_domain)
    if not a or not f:
        return False
    if (mode or "r").lower().startswith("s"):
        return a == f
    return organizational_domain(a) == organizational_domain(f)
