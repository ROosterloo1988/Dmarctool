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

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
