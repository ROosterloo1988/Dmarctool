"""SPF record analysis (RFC 7208).

Resolves the complete include tree once, counts DNS-querying terms (limit 10) and void
lookups (limit 2), and keeps the resolved data so we can later evaluate offline whether
a given source IP is authorised (used for recommendations).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from dmarc.dnscheck.findings import Finding
from dmarc.dnscheck.resolver import DnsLookupError, NoData, NxDomain, Resolver, TempError

LOOKUP_LIMIT = 10
VOID_LIMIT = 2
MX_LIMIT = 10
SAFETY_LIMIT = 40  # stop resolving after this many lookups (records far over the limit)
MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
DNS_TERMS = {"include", "a", "mx", "ptr", "exists", "redirect"}
_TERM = re.compile(r"^(?P<q>[+\-~?]?)(?P<name>[a-z0-9]+)(?P<rest>.*)$", re.IGNORECASE)
_CIDR = re.compile(r"^(?P<domain>[^/]*)(?:/(?P<v4>\d+))?(?://(?P<v6>\d+))?$")
QUALIFIER_RESULT = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}


class SpfSyntaxError(ValueError):
    pass


@dataclass
class Term:
    qualifier: str
    name: str  # mechanism or modifier name, lower case
    value: str | None
    v4: int | None = None
    v6: int | None = None
    is_modifier: bool = False
    # resolved data
    networks: list[str] = field(default_factory=list)
    child: SpfNode | None = None
    unresolvable: bool = False  # macros, exists, ptr: cannot be evaluated offline

    def as_dict(self) -> dict[str, Any]:
        d = {"term": self.text, "networks": self.networks}
        if self.child is not None:
            d["child"] = self.child.as_dict()
        if self.unresolvable:
            d["unresolvable"] = True
        return d

    @property
    def text(self) -> str:
        if self.is_modifier:
            return f"{self.name}={self.value}"
        q = "" if self.qualifier == "+" else self.qualifier
        s = f"{q}{self.name}"
        if self.value:
            s += f":{self.value}"
        if self.v4 is not None:
            s += f"/{self.v4}"
        if self.v6 is not None:
            s += f"//{self.v6}"
        return s


@dataclass
class SpfNode:
    domain: str
    record: str | None = None
    terms: list[Term] = field(default_factory=list)
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"domain": self.domain, "record": self.record, "error": self.error,
                "terms": [t.as_dict() for t in self.terms]}

    @property
    def redirect(self) -> Term | None:
        return next((t for t in self.terms if t.is_modifier and t.name == "redirect"), None)

    def includes(self) -> list[str]:
        """All include/redirect targets in this tree (lower case)."""
        out = []
        for t in self.terms:
            if t.name in ("include", "redirect") and t.value:
                out.append(t.value.lower())
                if t.child:
                    out.extend(t.child.includes())
        return out


def is_spf(txt: str) -> bool:
    return txt.strip().lower() == "v=spf1" or txt.strip().lower().startswith("v=spf1 ")


def parse_spf(record: str) -> list[Term]:
    tokens = record.split()
    if not tokens or tokens[0].lower() != "v=spf1":
        raise SpfSyntaxError("record does not start with v=spf1")
    terms: list[Term] = []
    for tok in tokens[1:]:
        m = re.match(r"^([a-z][a-z0-9_.\-]*)=(.*)$", tok, re.IGNORECASE)
        if m and m[1].lower() not in MECHANISMS:
            terms.append(Term("+", m[1].lower(), m[2], is_modifier=True))
            continue
        m = _TERM.match(tok)
        if not m or m["name"].lower() not in MECHANISMS:
            raise SpfSyntaxError(f"unknown mechanism '{tok}'")
        q, name, rest = m["q"] or "+", m["name"].lower(), m["rest"]
        term = Term(q, name, None)
        if name == "all":
            if rest:
                raise SpfSyntaxError(f"invalid term '{tok}'")
        elif name in ("ip4", "ip6"):
            if not rest.startswith(":"):
                raise SpfSyntaxError(f"'{tok}' needs an address")
            try:
                net = ipaddress.ip_network(rest[1:], strict=False)
            except ValueError as exc:
                raise SpfSyntaxError(f"invalid address in '{tok}'") from exc
            if (name == "ip4") != (net.version == 4):
                raise SpfSyntaxError(f"wrong address family in '{tok}'")
            term.value = rest[1:]
            term.networks = [str(net)]
        elif name in ("include", "exists"):
            if not rest.startswith(":") or len(rest) < 2:
                raise SpfSyntaxError(f"'{tok}' needs a domain")
            term.value = rest[1:]
        else:  # a, mx, ptr
            spec = rest[1:] if rest.startswith(":") else rest
            cm = _CIDR.match(spec)
            if not cm or (rest and not rest.startswith((":", "/"))):
                raise SpfSyntaxError(f"invalid term '{tok}'")
            term.value = cm["domain"] or None
            term.v4 = int(cm["v4"]) if cm["v4"] else None
            term.v6 = int(cm["v6"]) if cm["v6"] else None
            if (term.v4 is not None and term.v4 > 32) or (term.v6 is not None and term.v6 > 128):
                raise SpfSyntaxError(f"invalid prefix length in '{tok}'")
        terms.append(term)
    redirects = [t for t in terms if t.is_modifier and t.name == "redirect"]
    if len(redirects) > 1:
        raise SpfSyntaxError("more than one redirect= modifier")
    return terms


@dataclass
class SpfAnalysis:
    domain: str
    records: list[str]
    root: SpfNode | None
    lookups: int = 0
    void_lookups: int = 0
    findings: list[Finding] = field(default_factory=list)
    temp_error: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {"domain": self.domain, "records": self.records, "lookups": self.lookups,
                "void_lookups": self.void_lookups, "tree": self.root.as_dict() if self.root else None,
                "includes": self.root.includes() if self.root else []}

    def evaluate(self, ip: str) -> str:
        """Offline SPF evaluation of ``ip`` against the resolved tree.

        Returns pass/fail/softfail/neutral/none/permerror or 'unknown' when the outcome
        depends on terms we cannot evaluate offline (exists, ptr, macros).
        """
        if len(self.records) > 1:
            return "permerror"
        if self.root is None:
            return "none"
        if self.lookups > LOOKUP_LIMIT or any(f.code in ("spf.syntax", "spf.multiple") for f in self.findings):
            return "permerror"
        return _eval_node(self.root, ipaddress.ip_address(ip))


def _eval_node(node: SpfNode, ip) -> str:
    if node.error:
        return "permerror"
    uncertain = False
    for t in node.terms:
        if t.is_modifier:
            continue
        if t.name == "all":
            return "unknown" if uncertain else QUALIFIER_RESULT[t.qualifier]
        if t.unresolvable:
            uncertain = True
            continue
        if t.name == "include":
            if t.child is None:
                return "permerror"
            r = _eval_node(t.child, ip)
            if r == "pass":
                return QUALIFIER_RESULT[t.qualifier]
            if r in ("permerror", "unknown"):
                return r
            continue
        if any(ip in ipaddress.ip_network(n) for n in t.networks if ipaddress.ip_network(n).version == ip.version):
            return "unknown" if uncertain else QUALIFIER_RESULT[t.qualifier]
    redirect = node.redirect
    if redirect is not None and redirect.child is not None:
        return _eval_node(redirect.child, ip)
    return "unknown" if uncertain else "neutral"


class _Walker:
    def __init__(self, resolver: Resolver, analysis: SpfAnalysis):
        self.r = resolver
        self.a = analysis

    def lookup_txt(self, domain: str) -> list[str] | None:
        try:
            return [t for t in self.r.txt(domain) if is_spf(t)]
        except (NxDomain, NoData):
            return []
        except TempError:
            self.a.temp_error = True
            return None

    def addresses(self, domain: str, v4: int | None, v6: int | None) -> tuple[list[str], bool]:
        nets, void = [], True
        for fn, plen, maxlen in ((self.r.a, v4, 32), (self.r.aaaa, v6, 128)):
            try:
                for addr in fn(domain):
                    void = False
                    nets.append(str(ipaddress.ip_network(f"{addr}/{plen if plen is not None else maxlen}", strict=False)))
            except (NxDomain, NoData):
                pass
            except TempError:
                self.a.temp_error = True
                void = False
        return nets, void

    def count(self) -> bool:
        self.a.lookups += 1
        return self.a.lookups <= SAFETY_LIMIT

    def void(self, what: str) -> None:
        self.a.void_lookups += 1

    def walk(self, domain: str, record: str, stack: tuple[str, ...]) -> SpfNode:
        node = SpfNode(domain, record)
        try:
            node.terms = parse_spf(record)
        except SpfSyntaxError as exc:
            node.error = str(exc)
            self.a.findings.append(Finding("spf", "error", "spf.syntax",
                                           f"SPF syntax error in the record of {domain}: {exc}.",
                                           "Fix the record; a syntax error makes SPF fail (permerror) for all mail.",
                                           {"domain": domain, "record": record}))
            return node

        for t in node.terms:
            if t.name not in DNS_TERMS:
                continue
            if not self.count():
                t.unresolvable = True
                continue
            target = (t.value or domain).lower()
            if "%" in target:
                t.unresolvable = True  # macro, depends on the message
                continue
            if t.name in ("include", "redirect"):
                if target in stack:
                    self.a.findings.append(Finding("spf", "error", "spf.loop", f"SPF include loop via {target}.",
                                                   detail={"domain": target}))
                    t.child = SpfNode(target, error="loop")
                    continue
                recs = self.lookup_txt(target)
                if recs is None:
                    t.unresolvable = True
                elif not recs:
                    self.void(target)
                    t.child = SpfNode(target, error="no SPF record")
                    self.a.findings.append(Finding(
                        "spf", "error", "spf.include_without_record",
                        f"'{t.text}' points to a domain without an SPF record: SPF fails (permerror) for all mail.",
                        f"Remove '{t.text}' or correct the domain name.", {"term": t.text}))
                elif len(recs) > 1:
                    t.child = SpfNode(target, error="multiple SPF records")
                    self.a.findings.append(Finding("spf", "error", "spf.include_multiple",
                                                   f"{target} (via '{t.text}') has multiple SPF records.",
                                                   detail={"term": t.text}))
                else:
                    t.child = self.walk(target, recs[0], (*stack, target))
            elif t.name == "a":
                t.networks, void = self.addresses(target, t.v4, t.v6)
                if void:
                    self.void(target)
            elif t.name == "mx":
                try:
                    hosts = [h for _, h in sorted(self.r.mx(target))]
                except (NxDomain, NoData):
                    hosts = []
                    self.void(target)
                except TempError:
                    self.a.temp_error = True
                    t.unresolvable = True
                    continue
                if len(hosts) > MX_LIMIT:
                    self.a.findings.append(Finding("spf", "error", "spf.mx_limit",
                                                   f"'{t.text}' resolves to more than {MX_LIMIT} MX hosts (permerror)."))
                for h in hosts[:MX_LIMIT]:
                    nets, _ = self.addresses(h, t.v4, t.v6)
                    t.networks.extend(nets)
            elif t.name in ("ptr", "exists"):
                t.unresolvable = True
        return node


def check_spf(domain: str, resolver: Resolver) -> tuple[SpfAnalysis, list[Finding]]:
    analysis = SpfAnalysis(domain, [], None)
    w = _Walker(resolver, analysis)
    records = w.lookup_txt(domain)
    f = analysis.findings
    if records is None:
        f.append(Finding("spf", "warning", "spf.dns_error", "DNS lookup of the SPF record failed; will retry."))
        return analysis, f
    analysis.records = records
    if not records:
        f.append(Finding("spf", "error", "spf.missing", f"{domain} has no SPF record.",
                         f'Publish a TXT record at {domain}: "v=spf1 <includes of your senders> -all" '
                         '(or "v=spf1 -all" if the domain never sends mail).'))
        return analysis, f
    if len(records) > 1:
        f.append(Finding("spf", "error", "spf.multiple",
                         f"{domain} has {len(records)} SPF records. That is a permerror: SPF fails for all mail.",
                         "Merge them into one record (one v=spf1 ... line).", {"records": records}))
        return analysis, f

    analysis.root = w.walk(domain, records[0], (domain.lower(),))
    root = analysis.root
    if root.error:
        return analysis, f

    if analysis.lookups > LOOKUP_LIMIT:
        f.append(Finding("spf", "error", "spf.too_many_lookups",
                         f"The SPF record needs {analysis.lookups} DNS lookups (maximum {LOOKUP_LIMIT}). "
                         "Receivers return permerror: SPF fails for all mail.",
                         "Remove includes of services you no longer use, replace a/mx with ip4/ip6 "
                         "or move senders to a subdomain.", {"lookups": analysis.lookups}))
    elif analysis.lookups >= LOOKUP_LIMIT - 1:
        f.append(Finding("spf", "warning", "spf.near_lookup_limit",
                         f"The SPF record uses {analysis.lookups} of the {LOOKUP_LIMIT} allowed DNS lookups.",
                         "Adding another include will break SPF; clean up first.", {"lookups": analysis.lookups}))
    else:
        f.append(Finding("spf", "ok", "spf.lookups", f"The SPF record uses {analysis.lookups} of {LOOKUP_LIMIT} DNS lookups.",
                         detail={"lookups": analysis.lookups}))
    if analysis.void_lookups > VOID_LIMIT:
        f.append(Finding("spf", "error", "spf.void_lookups",
                         f"{analysis.void_lookups} lookups return no result (maximum {VOID_LIMIT}): permerror.",
                         "Remove includes/a/mx terms that point to non-existent names."))
    elif analysis.void_lookups:
        f.append(Finding("spf", "warning", "spf.void_lookup",
                         f"{analysis.void_lookups} lookup(s) in the SPF record return no result.",
                         "Remove terms that point to non-existent names."))

    # Final "all" (follow redirect for the effective one)
    effective, node = None, root
    for _ in range(10):
        all_terms = [t for t in node.terms if t.name == "all"]
        if all_terms:
            effective = all_terms[0]
            idx = node.terms.index(effective)
            if any(not t.is_modifier for t in node.terms[idx + 1:]) and node is root:
                f.append(Finding("spf", "warning", "spf.terms_after_all", "Terms after 'all' are never evaluated."))
            break
        if node.redirect is not None and node.redirect.child is not None and not node.redirect.child.error:
            node = node.redirect.child
            continue
        break
    if effective is None:
        f.append(Finding("spf", "warning", "spf.no_all",
                         "The SPF record has no 'all' at the end, so unknown servers get 'neutral'.",
                         "End the record with -all (or ~all)."))
    elif effective.qualifier == "+":
        f.append(Finding("spf", "error", "spf.plus_all", "'+all' allows the whole internet to send mail as this domain.",
                         "Replace +all with -all (or ~all)."))
    elif effective.qualifier == "?":
        f.append(Finding("spf", "warning", "spf.neutral_all", "'?all' gives no protection (neutral for every server).",
                         "Replace ?all with ~all or -all."))
    elif effective.qualifier == "~":
        f.append(Finding("spf", "info", "spf.softfail_all", "'~all': unknown servers get softfail. Fine together with DMARC."))
    else:
        f.append(Finding("spf", "ok", "spf.fail_all", "'-all': unknown servers fail SPF."))

    def walk_terms(n: SpfNode):
        for t in n.terms:
            yield n, t
            if t.child:
                yield from walk_terms(t.child)

    if any(t.name == "ptr" for _, t in walk_terms(root)):
        f.append(Finding("spf", "warning", "spf.ptr", "The 'ptr' mechanism is deprecated and slow; many receivers ignore it.",
                         "Replace ptr with ip4/ip6 or include."))
    if analysis.temp_error:
        f.append(Finding("spf", "warning", "spf.dns_error", "Some lookups in the SPF tree timed out; results may be incomplete."))
    return analysis, f
