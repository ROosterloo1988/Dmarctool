"""Management endpoints: domains, source classification, settings, jobs, processing log, users, audit."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from dmarc import appsettings
from dmarc.db import models as m
from dmarc.parsing.alignment import normalize_domain
from dmarc.worker import JOBS, queue_job

from .deps import CurrentUser, audit, csrf_protect, current_user, get_db, require_admin

router = APIRouter(prefix="/api", dependencies=[Depends(current_user), Depends(csrf_protect)])
DOMAIN_RE = r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$"


# --------------------------------------------------------------------------------------
# Domains
# --------------------------------------------------------------------------------------

class DomainIn(BaseModel):
    name: str = Field(max_length=253)
    parked: bool = False


class DomainPatch(BaseModel):
    parked: bool | None = None
    active: bool | None = None


@router.post("/domains", status_code=201)
def add_domain(body: DomainIn, request: Request, db: Session = Depends(get_db), user: CurrentUser = Depends(require_admin)):
    import re

    name = normalize_domain(body.name) or ""
    if not re.match(DOMAIN_RE, name):
        raise HTTPException(422, "invalid domain name")
    if db.scalars(select(m.Domain).where(m.Domain.name == name)).first():
        raise HTTPException(409, "domain already exists")
    db.add(m.Domain(name=name, parked=body.parked, active=True))
    audit(db, request, user.label, "domain_add", name, parked=body.parked)
    queue_job(db, "dnscheck", requested_by=user.label)
    return {"name": name}


@router.patch("/domains/{domain}")
def update_domain(domain: str, body: DomainPatch, request: Request, db: Session = Depends(get_db),
                  user: CurrentUser = Depends(require_admin)):
    d = db.scalars(select(m.Domain).where(m.Domain.name == domain.lower())).one_or_none()
    if d is None:
        raise HTTPException(404, "domain not found")
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(d, k, v)
    audit(db, request, user.label, "domain_update", d.name, **changes)
    return {"name": d.name, "parked": d.parked, "active": d.active}


@router.delete("/domains/{domain}", status_code=204)
def delete_domain(domain: str, request: Request, db: Session = Depends(get_db), user: CurrentUser = Depends(require_admin)):
    """Stops monitoring (DNS checks, dashboard). Report data is kept."""
    d = db.scalars(select(m.Domain).where(m.Domain.name == domain.lower())).one_or_none()
    if d is None:
        raise HTTPException(404, "domain not found")
    db.delete(d)
    audit(db, request, user.label, "domain_remove", domain)


@router.post("/domains/{domain}/dns/check", status_code=202)
def check_dns_now(domain: str, db: Session = Depends(get_db), user: CurrentUser = Depends(require_admin)):
    run = queue_job(db, "dnscheck", requested_by=user.label)
    return {"job": run.id, "status": run.status}


# --------------------------------------------------------------------------------------
# Source classification
# --------------------------------------------------------------------------------------

class ClassificationIn(BaseModel):
    status: Literal["legit", "unknown", "abuse"] | None
    note: str | None = Field(None, max_length=2000)


@router.put("/domains/{domain}/sources/{source_key}/classification")
def classify(domain: str, source_key: str, body: ClassificationIn, request: Request, db: Session = Depends(get_db),
             user: CurrentUser = Depends(require_admin)):
    domain = domain.lower()
    if body.status is None:
        row = db.scalars(select(m.SourceClassification).where(
            m.SourceClassification.domain == domain, m.SourceClassification.source_key == source_key)).one_or_none()
        if row:
            db.delete(row)
    else:
        stmt = pg_insert(m.SourceClassification).values(domain=domain, source_key=source_key[:64], status=body.status,
                                                         note=body.note, updated_by=user.label)
        db.execute(stmt.on_conflict_do_update(constraint="uq_source_classification", set_={
            "status": stmt.excluded.status, "note": stmt.excluded.note, "updated_by": stmt.excluded.updated_by,
            "updated_at": func.now()}))
    audit(db, request, user.label, "classify", f"{domain}:{source_key}", status=body.status, note=body.note)
    return {"source_key": source_key, "status": body.status, "note": body.note}


# --------------------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------------------

class SettingIn(BaseModel):
    value: Any


@router.get("/settings", dependencies=[Depends(require_admin)])
def get_settings_(request: Request, db: Session = Depends(get_db)):
    return appsettings.get_all(db, request.app.state.settings)


@router.put("/settings/{key}")
def put_setting(key: str, body: SettingIn, request: Request, db: Session = Depends(get_db),
                user: CurrentUser = Depends(require_admin)):
    try:
        old = appsettings.get_value(db, key, request.app.state.settings) if key in appsettings.DEFINITIONS else None
        value = appsettings.set_value(db, key, body.value, user=user.label)
    except appsettings.SettingError as exc:
        raise HTTPException(422, str(exc)) from None
    audit(db, request, user.label, "setting_change", key, old=old, new=value)
    return {"key": key, "value": value}


@router.delete("/settings/{key}")
def reset_setting(key: str, request: Request, db: Session = Depends(get_db), user: CurrentUser = Depends(require_admin)):
    try:
        appsettings.reset_value(db, key)
    except appsettings.SettingError as exc:
        raise HTTPException(422, str(exc)) from None
    audit(db, request, user.label, "setting_reset", key)
    return appsettings.get_all(db, request.app.state.settings)[key]


# --------------------------------------------------------------------------------------
# Processing: inbound messages and jobs
# --------------------------------------------------------------------------------------

@router.get("/inbound")
def inbound(status: str | None = Query(None, pattern="^(processed|duplicate|partial|failed|problems)$"),
            page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500), db: Session = Depends(get_db)):
    i = m.InboundMessage
    q = select(i)
    if status == "problems":
        q = q.where((i.status.in_(["partial", "failed"])) | (i.move_error.is_not(None)))
    elif status:
        q = q.where(i.status == status)
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    counts = dict(db.execute(select(i.status, func.count()).group_by(i.status)).all())
    counts["move_errors"] = db.scalar(select(func.count()).where(i.move_error.is_not(None))) or 0
    rows = db.scalars(q.order_by(i.processed_at.desc()).offset((page - 1) * page_size).limit(page_size))
    reports = {}
    ids = []
    items = []
    for r in rows:
        ids.append(r.id)
        items.append({"id": r.id, "source": r.source, "subject": r.subject, "sender": r.sender,
                      "received_at": r.received_at, "processed_at": r.processed_at, "kind": r.kind,
                      "status": r.status, "reports_new": r.reports_new, "reports_duplicate": r.reports_duplicate,
                      "errors": r.errors, "moved_to": r.moved_to, "move_error": r.move_error})
    if ids:
        for rid, inbound_id in db.execute(select(m.AggregateReport.id, m.AggregateReport.inbound_message_id)
                                          .where(m.AggregateReport.inbound_message_id.in_(ids))):
            reports.setdefault(inbound_id, []).append(rid)
    for it in items:
        it["report_ids"] = reports.get(it["id"], [])
    return {"total": total, "counts": counts, "items": items}


@router.get("/jobs")
def jobs(limit: int = Query(50, ge=1, le=500), db: Session = Depends(get_db)):
    j = m.JobRun
    rows = db.scalars(select(j).order_by(j.created_at.desc(), j.id.desc()).limit(limit))
    last = {}
    for job in JOBS:
        r = db.scalars(select(j).where(j.job == job, j.status.in_(["ok", "error", "skipped"]))
                       .order_by(j.started_at.desc().nulls_last()).limit(1)).first()
        if r:
            last[job] = {"status": r.status, "started_at": r.started_at, "finished_at": r.finished_at, "error": r.error}
    return {"last": last, "items": [
        {"id": r.id, "job": r.job, "status": r.status, "requested_by": r.requested_by, "created_at": r.created_at,
         "started_at": r.started_at, "finished_at": r.finished_at, "stats": r.stats, "error": r.error} for r in rows]}


@router.post("/jobs/{job}", status_code=202)
def run_job_now(job: str, request: Request, db: Session = Depends(get_db), user: CurrentUser = Depends(require_admin)):
    if job not in JOBS:
        raise HTTPException(404, "unknown job")
    run = queue_job(db, job, requested_by=user.label)
    audit(db, request, user.label, "job_queue", job)
    return {"id": run.id, "job": run.job, "status": run.status}


# --------------------------------------------------------------------------------------
# Users & audit
# --------------------------------------------------------------------------------------

class UserPatch(BaseModel):
    active: bool | None = None
    role: Literal["admin", "viewer"] | None = None


@router.get("/users", dependencies=[Depends(require_admin)])
def users(db: Session = Depends(get_db)):
    return [{"id": u.id, "name": u.name, "email": u.email, "role": u.role, "is_local": u.is_local, "active": u.active,
             "last_login": u.last_login, "locked": bool(u.locked_until and u.locked_until > datetime.now(UTC))}
            for u in db.scalars(select(m.User).order_by(m.User.name))]


@router.patch("/users/{uid}")
def update_user(uid: int, body: UserPatch, request: Request, db: Session = Depends(get_db),
                user: CurrentUser = Depends(require_admin)):
    u = db.get(m.User, uid)
    if u is None:
        raise HTTPException(404, "user not found")
    if u.id == user.id:
        raise HTTPException(422, "you cannot change your own account")
    if body.role is not None and not u.is_local:
        raise HTTPException(422, "roles of Entra ID users are managed in Entra ID (app role assignment)")
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(u, k, v)
    if body.active:
        u.locked_until, u.failed_logins = None, 0
    audit(db, request, user.label, "user_update", u.email or u.name, **changes)
    return {"id": u.id, "active": u.active, "role": u.role}


@router.get("/audit", dependencies=[Depends(require_admin)])
def audit_log(page: int = Query(1, ge=1), page_size: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)):
    a = m.AuditLog
    total = db.scalar(select(func.count()).select_from(a))
    rows = db.scalars(select(a).order_by(a.at.desc(), a.id.desc()).offset((page - 1) * page_size).limit(page_size))
    return {"total": total, "items": [{"id": r.id, "at": r.at, "user": r.user, "action": r.action, "target": r.target,
                                       "detail": r.detail, "ip": r.ip} for r in rows]}


# --------------------------------------------------------------------------------------
# Notifications
# --------------------------------------------------------------------------------------

@router.get("/notifications", dependencies=[Depends(require_admin)])
def notifications(limit: int = Query(50, ge=1, le=500), db: Session = Depends(get_db)):
    e = m.AlertEvent
    rows = db.scalars(select(e).order_by(e.created_at.desc(), e.id.desc()).limit(limit))
    open_problems = db.scalar(select(func.count()).select_from(m.AlertState).where(
        m.AlertState.status == "open", m.AlertState.domain != "*")) or 0
    return {"open_problems": open_problems, "items": [
        {"id": r.id, "created_at": r.created_at, "domain": r.domain, "kind": r.kind, "severity": r.severity,
         "title": r.title, "immediate": r.immediate, "sent_at": r.sent_at, "send_error": r.send_error} for r in rows]}


@router.post("/notifications/test")
def notifications_test(request: Request, db: Session = Depends(get_db), user: CurrentUser = Depends(require_admin)):
    from dmarc.alerts import send_test
    from dmarc.graph import GraphError

    factory = getattr(request.app.state, "mailbox_factory", None)
    if factory is None:
        from dmarc.worker import default_mailbox_factory

        factory = request.app.state.mailbox_factory = default_mailbox_factory(
            request.app.state.settings, request.app.state.sessions)
    try:
        recipients = send_test(db, factory, request.app.state.settings, requested_by=user.label)
    except (ValueError, GraphError) as exc:
        db.rollback()
        raise HTTPException(422, f"test mail not sent: {exc}") from None
    audit(db, request, user.label, "notify_test", ", ".join(recipients))
    return {"sent_to": recipients}


# --------------------------------------------------------------------------------------
# Microsoft 365 (Graph) connection
# --------------------------------------------------------------------------------------

class SecretIn(BaseModel):
    value: str = Field(min_length=1, max_length=2048)


def _graph_status(db: Session, settings) -> dict[str, Any]:
    from dmarc.graph import graph_credentials
    from dmarc.secrets_store import secret_status

    values = appsettings.get_all(db, settings)
    creds = graph_credentials(db, settings)
    return {
        "tenant_id": values["graph.tenant_id"],
        "client_id": values["graph.client_id"],
        "client_secret": secret_status(db, "graph.client_secret", settings)
                         | {"environment": bool(settings.graph_client_secret)},
        "certificate_configured": bool(settings.graph_certificate_path),
        "credential_source": creds.credential_source,
        "ready": bool(creds.tenant_id and creds.client_id and creds.credential_source != "none"),
    }


@router.get("/graph", dependencies=[Depends(require_admin)])
def graph_status(request: Request, db: Session = Depends(get_db)):
    return _graph_status(db, request.app.state.settings)


@router.put("/graph/secret")
def graph_set_secret(body: SecretIn, request: Request, db: Session = Depends(get_db),
                     user: CurrentUser = Depends(require_admin)):
    from dmarc.secrets_store import SecretStoreError, set_secret

    try:
        set_secret(db, "graph.client_secret", body.value, user.label, request.app.state.settings)
    except SecretStoreError as exc:
        raise HTTPException(422, str(exc)) from None
    audit(db, request, user.label, "secret_set", "graph.client_secret")  # never the value itself
    return _graph_status(db, request.app.state.settings)


@router.delete("/graph/secret")
def graph_delete_secret(request: Request, db: Session = Depends(get_db), user: CurrentUser = Depends(require_admin)):
    from dmarc.secrets_store import delete_secret

    if delete_secret(db, "graph.client_secret"):
        audit(db, request, user.label, "secret_delete", "graph.client_secret")
    return _graph_status(db, request.app.state.settings)


@router.post("/graph/test")
def graph_test(request: Request, db: Session = Depends(get_db), user: CurrentUser = Depends(require_admin)):
    """Check the connection step by step: token, read access to the source folder, folders."""
    from dmarc.graph import GraphError, GraphMailbox, graph_credentials, msal_token_provider

    settings = request.app.state.settings
    steps: list[dict[str, Any]] = []

    def step(name: str, ok: bool | None, detail: str) -> None:
        steps.append({"step": name, "ok": ok, "detail": detail})

    cfg = appsettings.mailbox_config(db, settings)
    try:
        token = msal_token_provider(settings, graph_credentials(db, settings))
        token()
        step("Access token", True, "Tenant ID, client ID and secret are valid.")
    except (GraphError, OSError, ValueError) as exc:
        step("Access token", False, str(exc))
        audit(db, request, user.label, "graph_test", None, ok=False)
        return {"ok": False, "steps": steps}
    if not cfg.address:
        step("Mailbox", False, "No mailbox address set (see Mailbox below).")
        return {"ok": False, "steps": steps}
    http = getattr(request.app.state, "graph_http", None)
    mb = GraphMailbox(cfg.address, token, settings, http=http) if http else GraphMailbox(cfg.address, token, settings)
    try:
        folder = mb.resolve_folder(cfg.source_folder)
        n = len(list(mb.list_messages(folder, 10)))
        step("Read access", True, f"'{cfg.source_folder}' in {cfg.address}: {n if n < 10 else '10+'} message(s) waiting.")
        for f in (cfg.processed_folder, cfg.failed_folder):
            try:
                mb.resolve_folder(f)
                step(f"Folder '{f}'", True, "exists")
            except GraphError as exc:
                if exc.status != 404:
                    raise
                step(f"Folder '{f}'", None, "does not exist yet; created on the first fetch")
    except GraphError as exc:
        step("Read access", False, str(exc))
    finally:
        if not http:
            mb.close()
    ok = all(x["ok"] is not False for x in steps)
    audit(db, request, user.label, "graph_test", cfg.address, ok=ok)
    return {"ok": ok, "steps": steps}
