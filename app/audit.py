"""Tamper-evident audit trail: each row's HMAC covers the previous row's hash (blockchain-style chain)."""
import hashlib
import hmac
import json
from contextvars import ContextVar

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .clock import utcnow
from .models import AuditLog, User
from .security import audit_key

request_ip: ContextVar[str | None] = ContextVar("request_ip", default=None)
GENESIS = "0" * 64


def _digest(prev, ts, actor_id, role, action, entity, entity_id, detail, ip) -> str:
    payload = json.dumps([prev, ts, actor_id, role, action, entity, entity_id, detail, ip], separators=(",", ":"))
    return hmac.new(audit_key(), payload.encode(), hashlib.sha256).hexdigest()


def audit(db: Session, actor: User | None, action: str, entity: str | None = None,
          entity_id: int | str | None = None, detail: dict | None = None) -> None:
    """Never put secrets/PII in `detail` -- ids and quantities only."""
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(727272)"))  # serialise chain appends
    prev = db.scalar(select(AuditLog.hash).order_by(AuditLog.id.desc()).limit(1)) or GENESIS
    ts = utcnow().isoformat(timespec="microseconds")
    detail_s = json.dumps(detail, sort_keys=True, default=str) if detail else None
    ip = request_ip.get()
    role = actor.role.value if actor else None
    aid = actor.id if actor else None
    h = _digest(prev, ts, aid, role, action, entity, None if entity_id is None else str(entity_id), detail_s, ip)
    db.add(AuditLog(ts=ts, actor_id=aid, actor_role=role, action=action, entity=entity,
                    entity_id=None if entity_id is None else str(entity_id), detail=detail_s, ip=ip,
                    prev_hash=prev, hash=h))


def verify_chain(db: Session) -> dict:
    prev, n = GENESIS, 0
    for row in db.scalars(select(AuditLog).order_by(AuditLog.id)):
        expect = _digest(prev, row.ts, row.actor_id, row.actor_role, row.action, row.entity, row.entity_id, row.detail, row.ip)
        if row.prev_hash != prev or not hmac.compare_digest(row.hash, expect):
            return {"valid": False, "broken_at_id": row.id, "checked": n}
        prev, n = row.hash, n + 1
    return {"valid": True, "checked": n}
