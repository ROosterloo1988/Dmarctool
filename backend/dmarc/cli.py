"""Command line interface: ``dmarc <command>``."""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from dmarc.config import get_settings


def _json_default(o: object) -> object:
    if isinstance(o, datetime):
        return o.isoformat()
    if isinstance(o, bytes):
        return f"<{len(o)} bytes>"
    raise TypeError(type(o))


def cmd_parse(args: argparse.Namespace) -> int:
    """Parse files and print the result as JSON, without touching the database."""
    from dmarc.parsing.message import parse_file

    rc = 0
    for path in _iter_files(args.paths):
        parsed = parse_file(path.read_bytes(), path.name)
        out = {
            "file": str(path),
            "kind": parsed.kind,
            "errors": parsed.errors,
            "aggregate": [dataclasses.asdict(r) for r in parsed.aggregate],
            "forensic": [dataclasses.asdict(r) for r in parsed.forensic],
        }
        print(json.dumps(out, indent=2, default=_json_default))
        rc |= 0 if parsed.ok else 1
    return rc


def cmd_import(args: argparse.Namespace) -> int:
    from dmarc.db.session import session_scope
    from dmarc.storage import ingest_file

    totals = {"processed": 0, "duplicate": 0, "partial": 0, "failed": 0}
    for path in _iter_files(args.paths):
        with session_scope() as session:
            outcome = ingest_file(session, path.read_bytes(), path.name)
        totals[outcome.status] += 1
        line = f"{outcome.status:<9} {outcome.kind:<4} new={outcome.new} dup={outcome.duplicate}  {path}"
        print(line)
        for e in outcome.errors:
            print(f"          ! {e}")
    print("summary: " + ", ".join(f"{k}={v}" for k, v in totals.items()))
    return 1 if totals["failed"] or totals["partial"] else 0


def cmd_migrate(args: argparse.Namespace) -> int:
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("script_location", str(Path(__file__).resolve().parent / "migrations"))
    command.upgrade(cfg, args.revision)
    return 0


def cmd_purge(args: argparse.Namespace) -> int:
    from dmarc.db.session import session_scope
    from dmarc.storage import purge_expired

    with session_scope() as session:
        print(json.dumps(purge_expired(session)))
    return 0


def cmd_domain(args: argparse.Namespace) -> int:
    from sqlalchemy import select

    from dmarc.db.models import Domain
    from dmarc.db.session import session_scope
    from dmarc.parsing.alignment import normalize_domain

    with session_scope() as session:
        if args.action == "add":
            for name in args.names:
                n = normalize_domain(name)
                if not session.execute(select(Domain).where(Domain.name == n)).scalar_one_or_none():
                    session.add(Domain(name=n, parked=args.parked))
                    print(f"added {n}")
        for d in session.execute(select(Domain).order_by(Domain.name)).scalars():
            print(f"{d.name}{'  (parked)' if d.parked else ''}{'' if d.active else '  (inactive)'}")
    return 0


def cmd_settings(args: argparse.Namespace) -> int:
    from dmarc.appsettings import SettingError, get_all, reset_value, set_value
    from dmarc.db.session import session_scope

    with session_scope() as session:
        try:
            if args.action == "set":
                if not args.key or args.value is None:
                    print("usage: dmarc settings set <key> <value>", file=sys.stderr)
                    return 2
                set_value(session, args.key, args.value, user="cli")
            elif args.action == "reset":
                reset_value(session, args.key)
        except SettingError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        for key, e in get_all(session).items():
            print(f"{key:<26} {e['value']!s:<32} ({e['source']})")
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    from dmarc.db.session import get_engine
    from dmarc.worker import Worker

    run = Worker(get_engine()).run_job("fetch")
    print(json.dumps({"status": run.status, "stats": run.stats, "error": run.error}, indent=2))
    return 0 if run.status == "ok" else 1


def cmd_queue(args: argparse.Namespace) -> int:
    from dmarc.db.session import session_scope
    from dmarc.worker import queue_job

    with session_scope() as session:
        run = queue_job(session, args.job, requested_by="cli")
        print(f"job {run.job} #{run.id} is {run.status}")
    return 0


def cmd_worker(args: argparse.Namespace) -> int:
    from dmarc.db.session import get_engine
    from dmarc.worker import Worker

    Worker(get_engine()).serve()
    return 0


def cmd_graph_check(args: argparse.Namespace) -> int:
    """Check the app registration and mailbox permissions step by step."""
    from dmarc.appsettings import mailbox_config
    from dmarc.db.session import session_scope
    from dmarc.graph import GraphError, GraphMailbox, msal_token_provider

    s = get_settings()
    with session_scope() as session:
        cfg = mailbox_config(session, s)
    address = args.mailbox or cfg.address

    def fail(label: str, exc: Exception) -> int:
        print(f"[FAIL] {label}: {exc}")
        return 1

    try:
        from dmarc.graph import graph_credentials

        with session_scope() as session:
            creds = graph_credentials(session, s)
        token = msal_token_provider(s, creds)
        token()
        print(f"[ OK ] access token obtained (credential from: {creds.credential_source})")
    except (GraphError, OSError, ValueError) as exc:
        return fail("access token", exc)
    if not address:
        return fail("mailbox", ValueError("not configured; run: dmarc settings set mailbox.address <address>"))

    mb = GraphMailbox(address, token, s)
    try:
        try:
            src = mb.resolve_folder(cfg.source_folder)
            n = len(list(mb.list_messages(src, 10)))
            print(f"[ OK ] read access to '{cfg.source_folder}' in {address} ({n if n < 10 else '10+'} messages waiting)")
        except GraphError as exc:
            return fail(f"read access to {address}", exc)
        for folder in (cfg.processed_folder, cfg.failed_folder):
            try:
                mb.resolve_folder(folder)
                print(f"[ OK ] folder '{folder}' exists")
            except GraphError as exc:
                if exc.status != 404:
                    return fail(f"folder '{folder}'", exc)
                print(f"[ -- ] folder '{folder}' does not exist yet; it is created on the first fetch")
        if args.other_mailbox:
            try:
                GraphMailbox(args.other_mailbox, token, s).resolve_folder("Inbox")
                print(f"[WARN] the app can ALSO read {args.other_mailbox}: access is not restricted to the DMARC mailbox!")
                return 1
            except GraphError as exc:
                if exc.status in (403, 404):
                    print(f"[ OK ] no access to {args.other_mailbox} (access is correctly restricted)")
                else:
                    return fail(f"restriction check on {args.other_mailbox}", exc)
    finally:
        mb.close()
    return 0


def cmd_dns_check(args: argparse.Namespace) -> int:
    from dmarc.dnscheck.resolver import DnsPythonResolver
    from dmarc.dnscheck.run import check_domain, run_dns_checks

    s = get_settings()
    resolver = DnsPythonResolver(s.dns_nameservers or None, s.dns_timeout_seconds)
    if args.domain:  # ad-hoc check without storing (selectors via --selector)
        result = check_domain(args.domain, resolver, [(args.domain, x) for x in args.selector], args.parked)
        _print_findings(args.domain, result["findings"])
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        return 1 if any(f["severity"] == "error" for f in result["findings"]) else 0

    from dmarc.db.session import session_scope
    from dmarc.dnscheck.run import latest_check

    with session_scope() as session:
        summary = run_dns_checks(session, s, resolver)
        for domain in summary:
            _print_findings(domain, latest_check(session, domain).findings)
    return 0


def _print_findings(domain: str, findings: list[dict]) -> None:
    icon = {"error": "ERROR", "warning": " WARN", "info": " INFO", "ok": "   OK"}
    print(f"== {domain}")
    for f in findings:
        print(f"  [{icon.get(f['severity'], f['severity'])}] {f['check']:<6} {f['message']}")
        if f.get("fix") and f["severity"] in ("error", "warning"):
            print(f"           -> {f['fix']}")


def cmd_enrich(args: argparse.Namespace) -> int:
    from dmarc.db.session import get_engine, session_scope
    from dmarc.worker import Worker

    if args.reassign:
        from dmarc.enrich import assign_sources
        from dmarc.senders import load_catalog

        with session_scope() as session:
            print(f"cleared and reassigned {assign_sources(session, load_catalog(), reassign=True)} records")
    run = Worker(get_engine()).run_job("enrich")
    print(json.dumps({"status": run.status, "stats": run.stats, "error": run.error}, indent=2))
    return 0 if run.status == "ok" else 1


def cmd_geoip_update(args: argparse.Namespace) -> int:
    from dmarc.geoip import download_dbip

    print(json.dumps(download_dbip(get_settings())))
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    from dmarc.analysis import readiness, recommendations, source_overview
    from dmarc.db.session import session_scope

    if args.days:
        get_settings().analysis_days = args.days
    with session_scope() as session:
        sources = source_overview(session, args.domain)
        ready = readiness(session, args.domain, sources=sources)
        recs = recommendations(session, args.domain, sources=sources)
        if args.json:
            print(json.dumps({"sources": [x.as_dict() for x in sources], "readiness": ready,
                              "recommendations": [r.as_dict() for r in recs]}, indent=2, default=str))
            return 0
        print(f"== {args.domain}: {ready['total_messages']} messages, legitimate pass rate "
              f"{ready['pass_rate']}%, policy p={ready['policy'] or '-'} -> {ready['status'].upper()}")
        for c in ready["criteria"]:
            print(f"  [{'x' if c['ok'] else ' '}] {c['text']}")
        print("\nSources:")
        for x in sources[: args.limit]:
            d = x.as_dict()
            print(f"  {d['messages']:>8}  pass {d['dmarc_pass_pct']:>5}%  spf-al {d['spf_aligned_pct']:>5}%  "
                  f"dkim-al {d['dkim_aligned_pct']:>5}%  {x.status or '-':<7} {x.name}  [{x.key}]")
        print("\nRecommendations:")
        for r in recs:
            print(f"  [{r.severity.upper()}] {r.title}")
            if r.text and r.text != r.title:
                print(f"      {r.text}")
            for a in r.actions:
                print(f"      -> {a}")
    return 0


def cmd_classify(args: argparse.Namespace) -> int:
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from dmarc.db.models import SourceClassification
    from dmarc.db.session import session_scope

    with session_scope() as session:
        stmt = pg_insert(SourceClassification).values(domain=args.domain, source_key=args.source_key,
                                                       status=args.status, note=args.note, updated_by="cli")
        session.execute(stmt.on_conflict_do_update(
            constraint="uq_source_classification",
            set_={"status": stmt.excluded.status, "note": stmt.excluded.note, "updated_by": "cli"}))
    print(f"{args.source_key} for {args.domain}: {args.status}")
    return 0


def cmd_user(args: argparse.Namespace) -> int:
    """Manage local break-glass accounts (Entra ID users are created on first sign-in)."""
    import getpass
    import os

    from sqlalchemy import select

    from dmarc.api.auth import hash_password
    from dmarc.db.models import User
    from dmarc.db.session import session_scope

    with session_scope() as session:
        if args.action == "list":
            for u in session.scalars(select(User).order_by(User.subject)):
                kind = "local" if u.is_local else "entra"
                print(f"{u.id:>4} {kind:<6} {u.role:<7} {'active' if u.active else 'disabled':<9} "
                      f"{u.email or u.name or u.subject}  last login: {u.last_login or '-'}")
            return 0
        if not args.username:
            print("username required", file=sys.stderr)
            return 2
        subject = f"local:{args.username.lower()}"
        user = session.scalars(select(User).where(User.subject == subject)).one_or_none()
        if args.action in ("add", "password"):
            pw = os.environ.get("DMARC_NEW_PASSWORD") or getpass.getpass("Password (min. 14 characters): ")
            if not os.environ.get("DMARC_NEW_PASSWORD") and getpass.getpass("Repeat: ") != pw:
                print("passwords do not match", file=sys.stderr)
                return 2
            try:
                pw_hash = hash_password(pw)
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            if user is None:
                if args.action == "password":
                    print("no such local user", file=sys.stderr)
                    return 2
                user = User(subject=subject, name=args.username, role=args.role, is_local=True, active=True,
                            failed_logins=0)
                session.add(user)
            user.password_hash, user.failed_logins, user.locked_until = pw_hash, 0, None
            if args.action == "add":
                user.role = args.role
            print(f"local user {args.username} saved ({user.role}). Local login must be enabled: "
                  "DMARC_LOCAL_LOGIN_ENABLED=true")
        elif args.action in ("disable", "enable"):
            if user is None:
                print("no such local user", file=sys.stderr)
                return 2
            user.active = args.action == "enable"
            print(f"{args.username} {args.action}d")
    return 0


def cmd_api(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("dmarc.api.app:app_factory", factory=True, host=args.host, port=args.port,
                proxy_headers=True, forwarded_allow_ips=args.forwarded_allow_ips, access_log=False)
    return 0


def cmd_graph_secret(args: argparse.Namespace) -> int:
    """Store or remove the Graph client secret (same as the admin portal; never printed)."""
    import getpass

    from dmarc.db.session import session_scope
    from dmarc.secrets_store import SecretStoreError, delete_secret, secret_status, set_secret

    with session_scope() as session:
        if args.action == "set":
            value = sys.stdin.readline().strip() if not sys.stdin.isatty() else getpass.getpass("Client secret: ")
            try:
                set_secret(session, "graph.client_secret", value, "cli")
            except SecretStoreError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
        elif args.action == "delete":
            delete_secret(session, "graph.client_secret")
        st = secret_status(session, "graph.client_secret")
        print("stored in database" + (f" by {st['updated_by']} at {st['updated_at']}" if st["stored"] else ": no")
              + ("" if st["readable"] in (None, True) else " (UNREADABLE: DMARC_SECRET_KEY changed?)"))
    return 0


def _iter_files(paths: list[str]):
    for p in map(Path, paths):
        if p.is_dir():
            yield from sorted(x for x in p.rglob("*") if x.is_file())
        else:
            yield p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    get_settings()
    parser = argparse.ArgumentParser(prog="dmarc")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("parse", help="parse report files/e-mails and print JSON (no database)")
    p.add_argument("paths", nargs="+")
    p.set_defaults(func=cmd_parse)

    p = sub.add_parser("import", help="import report files/e-mails (.eml, .xml, .gz, .zip) into the database")
    p.add_argument("paths", nargs="+")
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("migrate", help="apply database migrations")
    p.add_argument("revision", nargs="?", default="head")
    p.set_defaults(func=cmd_migrate)

    p = sub.add_parser("purge", help="delete forensic/aggregate data past its retention period")
    p.set_defaults(func=cmd_purge)

    p = sub.add_parser("domain", help="list or add monitored domains")
    p.add_argument("action", choices=["list", "add"])
    p.add_argument("names", nargs="*")
    p.add_argument("--parked", action="store_true")
    p.set_defaults(func=cmd_domain)

    p = sub.add_parser("settings", help="show or change runtime settings (mailbox address, folders, interval)")
    p.add_argument("action", nargs="?", choices=["list", "set", "reset"], default="list")
    p.add_argument("key", nargs="?")
    p.add_argument("value", nargs="?")
    p.set_defaults(func=cmd_settings)

    p = sub.add_parser("fetch", help="fetch and process mail from the mailbox once, now")
    p.set_defaults(func=cmd_fetch)

    p = sub.add_parser("queue", help="ask the running worker to run a job now")
    p.add_argument("job", choices=["fetch", "enrich", "dnscheck", "geoip", "purge"])
    p.set_defaults(func=cmd_queue)

    p = sub.add_parser("worker", help="run the background worker (scheduled fetch + purge)")
    p.set_defaults(func=cmd_worker)

    p = sub.add_parser("graph-check", help="verify the app registration and mailbox access")
    p.add_argument("--mailbox", help="mailbox address to test (default: configured one)")
    p.add_argument("--other-mailbox", help="a mailbox the app must NOT be able to read, to verify the restriction")
    p.set_defaults(func=cmd_graph_check)

    p = sub.add_parser("dns-check", help="check DMARC/SPF/DKIM of all monitored domains (or one, ad hoc)")
    p.add_argument("--domain", help="check this domain without storing the result")
    p.add_argument("--selector", action="append", default=[], help="DKIM selector to check (with --domain)")
    p.add_argument("--parked", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_dns_check)

    p = sub.add_parser("enrich", help="reverse DNS/ASN for source IPs, assign sources, rebuild daily stats")
    p.add_argument("--reassign", action="store_true", help="re-identify all sources (after a catalogue change)")
    p.set_defaults(func=cmd_enrich)

    p = sub.add_parser("geoip-update", help="download the DB-IP Lite ASN and country databases")
    p.set_defaults(func=cmd_geoip_update)

    p = sub.add_parser("analyze", help="sources, recommendations and p=reject readiness for a domain")
    p.add_argument("domain")
    p.add_argument("--days", type=int)
    p.add_argument("--limit", type=int, default=25)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("classify", help="mark a source as legit, unknown or abuse")
    p.add_argument("domain")
    p.add_argument("source_key", help="e.g. sender:sendgrid, asn:8075 or ip:192.0.2.1")
    p.add_argument("status", choices=["legit", "unknown", "abuse"])
    p.add_argument("--note")
    p.set_defaults(func=cmd_classify)

    p = sub.add_parser("user", help="manage local break-glass accounts")
    p.add_argument("action", choices=["list", "add", "password", "disable", "enable"])
    p.add_argument("username", nargs="?")
    p.add_argument("--role", choices=["admin", "viewer"], default="admin")
    p.set_defaults(func=cmd_user)

    p = sub.add_parser("graph-secret", help="store/remove the Graph client secret (value is read from stdin)")
    p.add_argument("action", choices=["status", "set", "delete"])
    p.set_defaults(func=cmd_graph_secret)

    p = sub.add_parser("api", help="run the web UI / API server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--forwarded-allow-ips", default=os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1"),
                   help="proxies whose X-Forwarded-* headers are trusted (the Application Gateway subnet)")
    p.set_defaults(func=cmd_api)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
