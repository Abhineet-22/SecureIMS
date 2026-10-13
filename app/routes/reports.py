import csv
import io
from datetime import date
from enum import Enum

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session, aliased

from .. import services
from ..db import get_db
from ..deps import staff_any
from ..schemas import QueryId
from ..models import (Asset, AdjustAction, Issue, IssueLine, Item, Renewal, ReturnRecord, StockAdjustment, Student, User)

router = APIRouter(prefix="/reports", tags=["reports"])


class Fmt(str, Enum):
    json = "json"
    csv = "csv"


def _safe(v):
    """CSV/Excel formula-injection guard: cells starting with = + - @ are neutralised."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def _csv(rows: list[dict], name: str) -> Response:
    buf = io.StringIO()
    if rows:
        w = csv.DictWriter(buf, fieldnames=list(rows[0]))
        w.writeheader()
        for r in rows:
            w.writerow({k: _safe(v) for k, v in r.items()})
    return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{name}.csv"'})


@router.get("/stock")
def stock(user: User = Depends(staff_any), db: Session = Depends(get_db), location_id: QueryId = None, format: Fmt = Fmt.json):
    """Total / available / issued / overdue / damaged / lost / maintenance per item."""
    rows = services.stock_summary(db, location_id=location_id)
    return _csv(rows, "stock-report") if format == Fmt.csv else rows


@router.get("/transactions")
def transactions(user: User = Depends(staff_any), db: Session = Depends(get_db), student_id: QueryId = None, item_id: QueryId = None,
                 programme: str | None = Query(None, max_length=80), location_id: QueryId = None, date_from: date | None = None,
                 date_to: date | None = None, limit: int = Query(500, ge=1, le=2000), format: Fmt = Fmt.json):
    """Unified ledger of issues, returns, renewals and stock adjustments (student-, item-, programme-, location-wise)."""
    ev: list[dict] = []
    loc = func.coalesce(Asset.location_id, Item.location_id)

    def rng(col, q):
        if date_from:
            q = q.where(col >= date_from)
        if date_to:
            q = q.where(col <= date_to)
        return q

    def base(q, line_cols=True):
        q = q.join(Item, Item.id == IssueLine.item_id).outerjoin(Asset, Asset.id == IssueLine.asset_id).join(Issue, Issue.id == IssueLine.issue_id).join(Student, Student.id == Issue.student_id)
        if student_id:
            q = q.where(Issue.student_id == student_id)
        if item_id:
            q = q.where(IssueLine.item_id == item_id)
        if programme:
            q = q.where(Student.programme == programme)
        if location_id:
            q = q.where(loc == location_id)
        return q

    staff_u = aliased(User)
    for ln, it, a, st, by in db.execute(rng(Issue.issue_date, base(select(IssueLine, Item, Asset, Student, staff_u.username).select_from(IssueLine)).join(staff_u, staff_u.id == Issue.issued_by_id)).limit(limit)):
        ev.append({"date": ln.issue.issue_date, "event": "ISSUE", "student": st.name, "enrolment_no": st.enrolment_no, "programme": st.programme, "item": it.name,
                   "asset_tag": a.asset_tag if a else None, "quantity": ln.qty_issued, "detail": f"due {ln.due_date}", "by": by})
    for rr, it, a, st, by in db.execute(rng(ReturnRecord.returned_on, base(select(ReturnRecord, Item, Asset, Student, staff_u.username).select_from(ReturnRecord).join(IssueLine, IssueLine.id == ReturnRecord.line_id)).join(staff_u, staff_u.id == ReturnRecord.received_by_id)).limit(limit)):
        ev.append({"date": rr.returned_on, "event": "RETURN", "student": st.name, "enrolment_no": st.enrolment_no, "programme": st.programme, "item": it.name,
                   "asset_tag": a.asset_tag if a else None, "quantity": rr.quantity, "detail": f"condition {rr.condition.value}", "by": by})
    for rn, it, a, st in db.execute(rng(Renewal.requested_on, base(select(Renewal, Item, Asset, Student).select_from(Renewal).join(IssueLine, IssueLine.id == Renewal.line_id))).limit(limit)):
        ev.append({"date": rn.decided_on or rn.requested_on, "event": f"RENEWAL_{rn.status.value}", "student": st.name, "enrolment_no": st.enrolment_no, "programme": st.programme,
                   "item": it.name, "asset_tag": a.asset_tag if a else None, "quantity": rn.line.outstanding, "detail": f"new due {rn.revised_due}" if rn.revised_due else (rn.remarks or ""),
                   "by": rn.decided_by.username if rn.decided_by else None})
    if not (student_id or programme):  # stock adjustments are not tied to a student
        q = select(StockAdjustment, Item, staff_u.username).join(Item, Item.id == StockAdjustment.item_id).join(staff_u, staff_u.id == StockAdjustment.by_id).outerjoin(Asset, Asset.id == StockAdjustment.asset_id)
        if item_id:
            q = q.where(StockAdjustment.item_id == item_id)
        if location_id:
            q = q.where(func.coalesce(Asset.location_id, Item.location_id) == location_id)
        for sa_, it, by in db.execute(rng(StockAdjustment.adjusted_on, q).limit(limit)):
            ev.append({"date": sa_.adjusted_on, "event": f"STOCK_{sa_.action}", "student": None, "enrolment_no": None, "programme": None, "item": it.name, "asset_tag": None,
                       "quantity": sa_.quantity, "detail": sa_.reason, "by": by})
    ev.sort(key=lambda e: (e["date"], e["event"]))
    ev = ev[:limit]
    return _csv(ev, "transactions") if format == Fmt.csv else ev
