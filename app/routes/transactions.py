from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from .. import services
from ..db import get_db
from ..deps import coordinator, staff_any, student_user
from ..errors import BusinessError
from ..models import Issue, IssueLine, Renewal, RenewalStatus, Student, User
from ..schemas import PathId, QueryId, AckOut, IssueIn, LineOut, RenewalDecisionIn, RenewalOut, RenewalRequestIn, ReturnIn

router = APIRouter(tags=["transactions"])


def _renewal_out(r: Renewal, with_student: bool) -> RenewalOut:
    ln = r.line
    return RenewalOut(id=r.id, line_id=r.line_id, item_name=ln.item.name, asset_tag=ln.asset.asset_tag if ln.asset else None,
                      student_id=ln.issue.student_id if with_student else None, requested_on=r.requested_on, reason=r.reason, status=r.status,
                      decided_on=r.decided_on, remarks=r.remarks, previous_due=r.previous_due, revised_due=r.revised_due)


# ================= staff: issue / return
@router.post("/issues", response_model=AckOut, status_code=201)
def issue(body: IssueIn, user: User = Depends(staff_any), db: Session = Depends(get_db)):
    return services.ack_view(db, services.issue_items(db, user, body))


@router.get("/issues/{issue_id}/acknowledgement", response_model=AckOut)
def acknowledgement(issue_id: PathId, user: User = Depends(staff_any), db: Session = Depends(get_db)):
    i = db.get(Issue, issue_id)
    if i is None:
        raise HTTPException(404, "Issue not found")
    return services.ack_view(db, i)


@router.post("/issue-lines/{line_id}/return", response_model=LineOut)
def return_items(line_id: PathId, body: ReturnIn, user: User = Depends(staff_any), db: Session = Depends(get_db)):
    ln = services.return_line(db, user, line_id, body)
    return services.line_views(db, [ln])[0]


@router.get("/issue-lines", response_model=list[LineOut])
def list_lines(user: User = Depends(staff_any), db: Session = Depends(get_db), student_id: QueryId = None, item_id: QueryId = None,
               open_only: bool = True, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    q = (select(IssueLine).options(joinedload(IssueLine.item), joinedload(IssueLine.asset)).order_by(IssueLine.due_date, IssueLine.id).limit(limit).offset(offset))
    if student_id:
        q = q.where(IssueLine.issue.has(Issue.student_id == student_id))
    if item_id:
        q = q.where(IssueLine.item_id == item_id)
    if open_only:
        q = q.where(IssueLine.status == "OPEN")
    return services.line_views(db, list(db.scalars(q).unique()))


# ================= staff: renewals
@router.get("/renewals", response_model=list[RenewalOut])
def list_renewals(user: User = Depends(staff_any), db: Session = Depends(get_db), status: RenewalStatus | None = None,
                  limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    q = select(Renewal).options(joinedload(Renewal.line).joinedload(IssueLine.item), joinedload(Renewal.line).joinedload(IssueLine.asset),
                                joinedload(Renewal.line).joinedload(IssueLine.issue)).order_by(Renewal.id.desc()).limit(limit).offset(offset)
    if status:
        q = q.where(Renewal.status == status)
    return [_renewal_out(r, True) for r in db.scalars(q).unique()]


@router.post("/renewals/{renewal_id}/decision", response_model=RenewalOut)
def decide(renewal_id: PathId, body: RenewalDecisionIn, user: User = Depends(coordinator), db: Session = Depends(get_db)):
    return _renewal_out(services.decide_renewal(db, user, renewal_id, body), True)


# ================= staff: overdue / upcoming
@router.get("/overdue")
def overdue(user: User = Depends(staff_any), db: Session = Depends(get_db)):
    lines = services.overdue_lines(db)
    return [{"line_id": l.id, "student_id": l.issue.student_id, "enrolment_no": l.issue.student.enrolment_no, "student_name": l.issue.student.name,
             "item": l.item.name, "asset_tag": l.asset.asset_tag if l.asset else None, "outstanding": l.outstanding, "due_date": l.due_date,
             "overdue_days": (services.today() - l.due_date).days, "message": services.overdue_text(l, False)} for l in lines]


@router.get("/upcoming")
def upcoming(user: User = Depends(staff_any), db: Session = Depends(get_db), days: int = Query(3, ge=0, le=15)):
    return [{"line_id": l.id, "student_id": l.issue.student_id, "enrolment_no": l.issue.student.enrolment_no, "item": l.item.name,
             "asset_tag": l.asset.asset_tag if l.asset else None, "outstanding": l.outstanding, "due_date": l.due_date,
             "message": services.upcoming_text(l, False)} for l in services.upcoming_lines(db, days)]


# ================= student self-service (identity ALWAYS comes from the token, never from a request parameter)
me = APIRouter(prefix="/me", tags=["student"])


@me.get("/issues", response_model=list[LineOut])
def my_issues(user: User = Depends(student_user), db: Session = Depends(get_db)):
    q = (select(IssueLine).options(joinedload(IssueLine.item), joinedload(IssueLine.asset))
         .where(IssueLine.status == "OPEN", IssueLine.issue.has(Issue.student_id == user.student_id)).order_by(IssueLine.due_date))
    return services.line_views(db, list(db.scalars(q).unique()))


@me.get("/history", response_model=list[LineOut])
def my_history(user: User = Depends(student_user), db: Session = Depends(get_db), limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    q = (select(IssueLine).options(joinedload(IssueLine.item), joinedload(IssueLine.asset))
         .where(IssueLine.issue.has(Issue.student_id == user.student_id)).order_by(IssueLine.id.desc()).limit(limit).offset(offset))
    return services.line_views(db, list(db.scalars(q).unique()))


@me.get("/renewals", response_model=list[RenewalOut])
def my_renewals(user: User = Depends(student_user), db: Session = Depends(get_db)):
    q = (select(Renewal).options(joinedload(Renewal.line).joinedload(IssueLine.item), joinedload(Renewal.line).joinedload(IssueLine.asset),
                                 joinedload(Renewal.line).joinedload(IssueLine.issue))
         .where(Renewal.line.has(IssueLine.issue.has(Issue.student_id == user.student_id))).order_by(Renewal.id.desc()))
    return [_renewal_out(r, False) for r in db.scalars(q).unique()]


@me.post("/renewals", response_model=RenewalOut, status_code=201)
def request_renewal(body: RenewalRequestIn, user: User = Depends(student_user), db: Session = Depends(get_db)):
    return _renewal_out(services.request_renewal(db, user, body), False)


@me.get("/reminders")
def my_reminders(user: User = Depends(student_user), db: Session = Depends(get_db), days: int = Query(3, ge=0, le=15)):
    return {"overdue": [services.overdue_text(l, True) for l in services.overdue_lines(db, user.student_id)],
            "due_soon": [services.upcoming_text(l, True) for l in services.upcoming_lines(db, days, user.student_id)]}
