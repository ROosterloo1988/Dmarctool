"""DMARC record lookup and validation (RFC 7489, plus DMARCbis tags np/t/psd)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from dmarc.dnscheck.findings import Finding
from dmarc.dnscheck.resolver import DnsLookupError, Resolver, TempError
from dmarc.parsing.alignment import organizational_domain

KNOWN_TAGS = {"v", "p", "sp", "np", "pct", "adkim", "aspf", "fo", "rf", "ri", "rua", "ruf", "t", "psd"}
POLICIES = {"none", "quarantine", "reject"}
_URI_SIZE = re.compile(r"^(?P<uri>.+?)(?:!(?P<size>\d+[kmgt]?))?$", re.IGNORECASE)


@dataclass
class DmarcRecord:
    raw: str
    tags: dict[str, str] = field(default_factory=dict)
    rua: list[str] = field(default_factory=list)  # e-mail addresses
    ruf: list[str] = field(default_factory=list)

    @property
    def p(self) -> str | None:
        return self.tags.get("p")

    @property
    def pct(self) -> int:
        try:
            return int(self.tags.get("pct", "100"))
        except ValueError:
            return 100


def is_dmarc(txt: str) -> bool:
    return re.match(r"^\s*v\s*=\s*DMARC1\s*(;|$)", txt, re.IGNORECASE) is not None


def parse_dmarc(txt: str, findings: list[Finding]) -> DmarcRecord:
    rec = DmarcRecord(raw=txt)
    parts = [p.strip() for p in txt.split(";")]
    for i, part in enumerate(parts):
        if not part:
            continue
        if "=" not in part:
            findings.append(Finding("dmarc", "error", "dmarc.syntax", f"Invalid part '{part}' in the DMARC record.",
                                    "Every part must look like tag=value, separated by semicolons."))
            continue
        k, v = (x.strip() for x in part.split("=", 1))
        k = k.lower()
        if i == 0 and k != "v":
            findings.append(Finding("dmarc", "error", "dmarc.syntax", "The DMARC record must start with v=DMARC1."))
        if k in rec.tags:
            findings.append(Finding("dmarc", "warning", "dmarc.duplicate_tag", f"Tag '{k}' appears more than once; only the first is used."))
            continue
        if k not in KNOWN_TAGS:
            findings.append(Finding("dmarc", "warning", "dmarc.unknown_tag", f"Unknown tag '{k}' is ignored by receivers.",
                                    "Check for typos (e.g. 'rua', 'ruf', 'sp')."))
        rec.tags[k] = v

    def bad(tag: str, expected: str) -> None:
        findings.append(Finding("dmarc", "error", "dmarc.invalid_value",
                                f"Invalid value '{rec.tags[tag]}' for '{tag}' (expected {expected}).",
                                detail={"tag": tag}))

    for tag in ("p", "sp", "np"):
        if tag in rec.tags:
            rec.tags[tag] = rec.tags[tag].lower()
            if rec.tags[tag] not in POLICIES:
                bad(tag, "none, quarantine or reject")
    for tag in ("adkim", "aspf"):
        if tag in rec.tags:
            rec.tags[tag] = rec.tags[tag].lower()
            if rec.tags[tag] not in ("r", "s"):
                bad(tag, "r or s")
    if "pct" in rec.tags and not (rec.tags["pct"].isdigit() and 0 <= int(rec.tags["pct"]) <= 100):
        bad("pct", "a number 0-100")
    if "fo" in rec.tags and not all(x.strip() in ("0", "1", "d", "s") for x in rec.tags["fo"].split(":")):
        bad("fo", "0, 1, d, s separated by ':'")
    if "ri" in rec.tags and not rec.tags["ri"].isdigit():
        bad("ri", "a number of seconds")

    if "p" not in rec.tags:
        if "rua" in rec.tags:
            findings.append(Finding("dmarc", "warning", "dmarc.p_missing",
                                    "The record has no 'p' tag; receivers treat it as p=none.", "Add p=none (or stricter)."))
            rec.tags["p"] = "none"
        else:
            findings.append(Finding("dmarc", "error", "dmarc.p_missing", "The record has no 'p' tag and is ignored.",
                                    "Add p=none (or stricter)."))

    for tag, target in (("rua", rec.rua), ("ruf", rec.ruf)):
        for uri in filter(None, (u.strip() for u in rec.tags.get(tag, "").split(","))):
            m = _URI_SIZE.match(uri)
            u = m["uri"] if m else uri
            if not u.lower().startswith("mailto:") or "@" not in u:
                findings.append(Finding("dmarc", "error", "dmarc.invalid_uri",
                                        f"'{uri}' in {tag} is not a valid mailto: address.",
                                        f"Use {tag}=mailto:address@domain.", {"tag": tag}))
                continue
            target.append(u[7:].strip().lower())
    return rec


def lookup_dmarc(domain: str, resolver: Resolver) -> tuple[list[str], str | None]:
    """Return (DMARC TXT records at _dmarc.<domain>, error)."""
    try:
        return [t for t in resolver.txt(f"_dmarc.{domain}") if is_dmarc(t)], None
    except TempError as exc:
        return [], str(exc)
    except DnsLookupError:
        return [], None


def check_dmarc(domain: str, resolver: Resolver) -> tuple[dict[str, Any], list[Finding]]:
    findings: list[Finding] = []
    result: dict[str, Any] = {"records": [], "policy_domain": domain, "inherited": False}

    records, err = lookup_dmarc(domain, resolver)
    if err:
        findings.append(Finding("dmarc", "warning", "dmarc.dns_error", f"DNS lookup failed: {err}. Will retry."))
        return result, findings

    org = organizational_domain(domain)
    if not records and org != domain:
        records, err = lookup_dmarc(org, resolver)
        if records:
            result["inherited"] = True
            result["policy_domain"] = org
            findings.append(Finding("dmarc", "info", "dmarc.inherited",
                                    f"No own DMARC record; {domain} inherits the policy of {org} (sp= applies)."))

    result["records"] = records
    if not records:
        findings.append(Finding("dmarc", "error", "dmarc.missing", f"No DMARC record found at _dmarc.{domain}.",
                                f'Publish a TXT record at _dmarc.{domain}: "v=DMARC1; p=none; rua=mailto:<report address>"'))
        return result, findings
    if len(records) > 1:
        findings.append(Finding("dmarc", "error", "dmarc.multiple",
                                f"There are {len(records)} DMARC records. Receivers then ignore DMARC completely!",
                                f"Remove all but one TXT record at _dmarc.{result['policy_domain']}.",
                                {"records": records}))
        return result, findings

    rec = parse_dmarc(records[0], findings)
    result["tags"] = rec.tags
    result["rua"] = rec.rua
    result["ruf"] = rec.ruf
    p = rec.tags.get("p")
    effective = rec.tags.get("sp", p) if result["inherited"] else p
    result["effective_policy"] = effective

    if effective == "none":
        findings.append(Finding("dmarc", "info", "dmarc.p_none",
                                "Policy is p=none: monitoring only, spoofed mail is still delivered.",
                                "Move to p=quarantine and then p=reject once all legitimate senders pass."))
    elif effective == "quarantine":
        findings.append(Finding("dmarc", "info", "dmarc.p_quarantine", "Policy is p=quarantine: failing mail goes to spam.",
                                "Move to p=reject once the reports show no legitimate failures."))
    elif effective == "reject":
        findings.append(Finding("dmarc", "ok", "dmarc.p_reject", "Policy is p=reject: failing mail is refused."))
    if rec.pct < 100 and effective in ("quarantine", "reject"):
        findings.append(Finding("dmarc", "warning", "dmarc.pct_partial",
                                f"pct={rec.pct}: the policy only applies to {rec.pct}% of failing mail.",
                                "Increase pct step by step to 100 (or remove pct)."))
    if p in ("quarantine", "reject") and rec.tags.get("sp") == "none" and not result["inherited"]:
        findings.append(Finding("dmarc", "warning", "dmarc.sp_weaker",
                                "sp=none: subdomains are not protected and can be spoofed.", "Remove sp= or set it equal to p."))
    if rec.ruf and rec.tags.get("fo", "0").strip() == "0":
        findings.append(Finding("dmarc", "info", "dmarc.ruf_fo",
                                "Failure reports (ruf) are only sent when both SPF and DKIM fail (fo=0, the default).",
                                "Add fo=1 to receive a failure report when SPF or DKIM fails."))
    if not rec.rua:
        findings.append(Finding("dmarc", "warning", "dmarc.no_rua", "No rua= address: you receive no aggregate reports.",
                                "Add rua=mailto:<report address>."))

    # External destination verification (RFC 7489 section 7.1)
    policy_org = organizational_domain(result["policy_domain"])
    verified: dict[str, bool] = {}
    for addr in rec.rua + rec.ruf:
        dest = addr.rsplit("@", 1)[1]
        if organizational_domain(dest) == policy_org or dest in verified:
            continue
        name = f"{result['policy_domain']}._report._dmarc.{dest}"
        try:
            ok = any(is_dmarc(t) for t in resolver.txt(name))
        except TempError:
            continue
        except DnsLookupError:
            ok = False
        verified[dest] = ok
        if not ok:
            findings.append(Finding("dmarc", "error", "dmarc.external_unverified",
                                    f"Reports go to {dest}, but {dest} has not authorised this: reporters will not send them.",
                                    f'The owner of {dest} must publish TXT "v=DMARC1" at {name}.',
                                    {"destination": dest, "record_name": name}))
    result["external_destinations"] = verified
    return result, findings
