from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2, "ok": 3}


@dataclass
class Finding:
    check: str  # dmarc | spf | dkim | parked
    severity: str  # error | warning | info | ok
    code: str  # stable identifier, e.g. 'dmarc.multiple'
    message: str  # plain-English explanation
    fix: str | None = None  # concrete action, if any
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.check, f.code))
