"""Command line interface: ``dmarc <command>``."""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
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
        token = msal_token_provider(s)
        token()
        print("[ OK ] access token obtained (tenant id, client id and credential are valid)")
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
    p.add_argument("job", choices=["fetch", "purge"])
    p.set_defaults(func=cmd_queue)

    p = sub.add_parser("worker", help="run the background worker (scheduled fetch + purge)")
    p.set_defaults(func=cmd_worker)

    p = sub.add_parser("graph-check", help="verify the app registration and mailbox access")
    p.add_argument("--mailbox", help="mailbox address to test (default: configured one)")
    p.add_argument("--other-mailbox", help="a mailbox the app must NOT be able to read, to verify the restriction")
    p.set_defaults(func=cmd_graph_check)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
