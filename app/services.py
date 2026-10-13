"""Business rules. Every function is one atomic transaction: any failure => rollback => stock and due dates untouched."""
import secrets
from datetime import date, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session, joinedload

from .audit import audit
from .clock import today
from .errors import BusinessError
from .models import (USABLE_CONDITIONS, AdjustAction, Asset, AssetStatus, Bucket, Condition, Issue, IssueLine, Item,
                     ItemKind, LineStatus, Policy, Renewal, RenewalStatus, ReturnRecord, StockAdjustment, Student,
                     User)
from .schemas import (AckOut, AdjustIn, AssetIn, AssetStatusIn, IssueIn, ItemIn, LineOut, RenewalDecisionIn,
                      RenewalRequestIn, ReturnIn)

ISSUE_PERIOD_DAYS = 15  # Rule 5 / 8: fixed by the problem statement

_WORDS = "zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty".split()
_COL = {Bucket.AVAILABLE: "qty_available", Bucket.DAMAGED: "qty_damaged", Bucket.LOST: "qty_lost", Bucket.MAINTENANCE: "qty_maintenance"}
_COND_TO_STATUS = {
    Condition.GOOD: AssetStatus.AVAILABLE, Condition.FAIR: AssetStatus.AVAILABLE, Condition.DAMAGED: AssetStatus.DAMAGED,
    Condition.NEEDS_MAINTENANCE: AssetStatus.MAINTENANCE, Condition.LOST: AssetStatus.LOST,
}
_COND_TO_BUCKET = {
    Condition.GOOD: Bucket.AVAILABLE, Condition.FAIR: Bucket.AVAILABLE, Condition.DAMAGED: Bucket.DAMAGED,
    Condition.NEEDS_MAINTENANCE: Bucket.MAINTENANCE, Condition.LOST: Bucket.LOST,
}


def words(n: int) -> str:
    return _WORDS[n] if 0 <= n < len(_WORDS) else str(n)


def plural(n: int, singular: str, plural_: str | None = None) -> str:
    return singular if n == 1 else (plural_ or singular + "s")


def get_policy(db: Session) -> Policy:
    return db.get(Policy, 1)


# ------------------------------------------------------------------ views
def line_views(db: Session, lines: list[IssueLine]) -> list[LineOut]:
    t = today()
    ids = [ln.id for ln in lines]
    pending = set(db.scalars(select(Renewal.line_id).where(Renewal.status == RenewalStatus.PENDING, Renewal.line_id.in_(ids)))) if ids else set()
    out = []
    for ln in lines:
        overdue = ln.status == LineStatus.OPEN and t > ln.due_date
        out.append(LineOut(
            line_id=ln.id, item_code=ln.item.code, item_name=ln.item.name, asset_tag=ln.asset.asset_tag if ln.asset else None,
            quantity_issued=ln.qty_issued, quantity_returned=ln.qty_returned, outstanding=ln.outstanding, due_date=ln.due_date,
            renewals_used=ln.renewal_count, status=ln.status, overdue=overdue,
            overdue_days=(t - ln.due_date).days if overdue else 0, pending_renewal=ln.id in pending))
    return out


def overdue_text(ln: IssueLine, for_student: bool) -> str:
    t = today()
    d = (t - ln.due_date).days
    what = f"{ln.item.name} {ln.asset.asset_tag}" if ln.asset else f"{ln.outstanding} x {ln.item.name}"
    who = "you" if for_student else f"student enrolment number {ln.issue.student.enrolment_no}"
    return (f"{what} issued to {who} was due on {ln.due_date:%d %B %Y} and is overdue by "
            f"{words(d)} {plural(d, 'day')}." + (f" Outstanding quantity: {ln.outstanding}." if not ln.asset else ""))


def upcoming_text(ln: IssueLine, for_student: bool) -> str:
    d = (ln.due_date - today()).days
    what = f"{ln.item.name} {ln.asset.asset_tag}" if ln.asset else f"{ln.outstanding} x {ln.item.name}"
    who = "you" if for_student else f"student enrolment number {ln.issue.student.enrolment_no}"
    when = "today" if d == 0 else f"in {words(d)} {plural(d, 'day')}"
    return f"{what} issued to {who} is due {when} ({ln.due_date:%d %B %Y})."


def _open_lines():
    return (select(IssueLine).where(IssueLine.status == LineStatus.OPEN)
            .options(joinedload(IssueLine.item), joinedload(IssueLine.asset), joinedload(IssueLine.issue).joinedload(Issue.student))
            .order_by(IssueLine.due_date, IssueLine.id))


def overdue_lines(db: Session, student_id: int | None = None) -> list[IssueLine]:
    q = _open_lines().where(IssueLine.due_date < today())
    if student_id is not None:
        q = q.where(IssueLine.issue.has(Issue.student_id == student_id))
    return list(db.scalars(q).unique())


def upcoming_lines(db: Session, days: int, student_id: int | None = None) -> list[IssueLine]:
    t = today()
    q = _open_lines().where(IssueLine.due_date >= t, IssueLine.due_date <= t + timedelta(days=days))
    if student_id is not None:
        q = q.where(IssueLine.issue.has(Issue.student_id == student_id))
    return list(db.scalars(q).unique())


def ack_view(db: Session, issue: Issue) -> AckOut:
    s = issue.student
    return AckOut(
        ack_no=issue.ack_no, issue_id=issue.id, student_name=s.name, enrolment_no=s.enrolment_no, programme=s.programme,
        purpose=issue.purpose, issue_date=issue.issue_date, issued_by=issue.issued_by.username, lines=line_views(db, issue.lines),
        note=f"Items must be returned or renewed (with coordinator approval) within {ISSUE_PERIOD_DAYS} days of the issue date.")


# ------------------------------------------------------------------ issue
def _issue_one_line(db: Session, issue: Issue, due: date, item_id: int, asset_id: int | None, qty: int) -> None:
    item = db.get(Item, item_id)
    if item is None or not item.is_active:
        raise BusinessError(f"Item {item_id} does not exist or has been retired.", 404)
    if item.kind == ItemKind.ASSET:
        if asset_id is None:
            raise BusinessError(f"'{item.name}' is individually tracked; choose a specific asset ID.", 422)
        if qty != 1:
            raise BusinessError("An individually tracked asset can only be issued one at a time.", 422)
        asset = db.get(Asset, asset_id)
        if asset is None or asset.item_id != item.id:
            raise BusinessError(f"Asset {asset_id} does not belong to item '{item.name}'.", 404)
        if asset.status == AssetStatus.ISSUED:
            raise BusinessError(f"Asset {asset.asset_tag} is already issued to another student.")
        if asset.status != AssetStatus.AVAILABLE:
            raise BusinessError(f"Asset {asset.asset_tag} is {asset.status.value.lower()} and stays unavailable until the coordinator updates its status.")
        if asset.condition not in USABLE_CONDITIONS:
            raise BusinessError(f"Asset {asset.asset_tag} is not in usable condition ({asset.condition.value.lower()}).")
        # atomic compare-and-set: two concurrent requests can never both win
        res = db.execute(update(Asset).where(Asset.id == asset.id, Asset.status == AssetStatus.AVAILABLE).values(status=AssetStatus.ISSUED))
        if res.rowcount != 1:
            raise BusinessError(f"Asset {asset.asset_tag} was just issued to someone else.")
    else:
        if asset_id is not None:
            raise BusinessError(f"'{item.name}' is tracked by quantity; do not supply an asset ID.", 422)
        if item.max_issue_qty and qty > item.max_issue_qty:
            raise BusinessError(f"Policy limit: at most {item.max_issue_qty} x {item.name} can be issued at once (requested {qty}).")
        res = db.execute(update(Item).where(Item.id == item.id, Item.qty_available >= qty)
                         .values(qty_available=Item.qty_available - qty, qty_issued=Item.qty_issued + qty))
        if res.rowcount != 1:
            db.refresh(item)
            av = item.qty_available
            name = item.name if item.name.endswith("s") or qty == 1 else item.name + "s"
            raise BusinessError(
                f"{words(qty).capitalize()} {name} {'was' if qty == 1 else 'were'} requested, but "
                + (f"only {words(av)} {'is' if av == 1 else 'are'} currently available." if av else "none are currently available."))
    db.add(IssueLine(issue_id=issue.id, item_id=item.id, asset_id=asset_id, qty_issued=qty, due_date=due))
    db.flush()


def issue_items(db: Session, actor: User, data: IssueIn) -> Issue:
    t = today()
    student = db.get(Student, data.student_id)
    if student is None or not student.is_active:
        raise BusinessError("Items can be issued only to registered students; this student is not registered or is inactive.", 422)
    pol = get_policy(db)
    issue_date = data.issue_date or t
    if issue_date > t:
        raise BusinessError("The issue date cannot be in the future.", 422)
    if (t - issue_date).days > pol.max_backdate_days:
        raise BusinessError(f"The issue date cannot be more than {pol.max_backdate_days} days in the past.", 422)
    keys = [("A", ln.asset_id) if ln.asset_id else ("I", ln.item_id) for ln in data.lines]
    if len(set(keys)) != len(keys):
        raise BusinessError("The same item/asset appears twice in this request; merge the lines.", 422)
    if pol.block_issue_if_overdue and (n := len(overdue_lines(db, student.id))):
        raise BusinessError(f"This student has {n} overdue {plural(n, 'item')}; new issues are blocked until they are returned.")
    open_n = db.scalar(select(func.count()).select_from(IssueLine).join(Issue).where(Issue.student_id == student.id, IssueLine.status == LineStatus.OPEN))
    if open_n + len(data.lines) > pol.max_open_lines_per_student:
        raise BusinessError(f"Issue limit reached: a student may hold at most {pol.max_open_lines_per_student} issued lines "
                            f"(currently {open_n}, requested {len(data.lines)}).")

    issue = Issue(ack_no=f"ACK-{issue_date:%Y%m%d}-{secrets.token_hex(4).upper()}", student_id=student.id,
                  issued_by_id=actor.id, issue_date=issue_date, purpose=data.purpose)
    db.add(issue)
    db.flush()
    due = issue_date + timedelta(days=ISSUE_PERIOD_DAYS)
    errors: list[str] = []
    for ln in data.lines:
        try:
            _issue_one_line(db, issue, due, ln.item_id, ln.asset_id, ln.quantity)
        except BusinessError as e:
            errors.extend(e.reasons)
    if errors:  # raising => session closes => EVERYTHING above is rolled back (no partial issue)
        raise BusinessError("The items could not be issued: " + " ".join(errors), 409, errors)
    audit(db, actor, "ISSUE", "issue", issue.id, {"student_id": student.id, "ack": issue.ack_no, "due": due.isoformat(),
                                                  "lines": [[l.item_id, l.asset_id, l.quantity] for l in data.lines]})
    db.commit()
    db.refresh(issue)
    return issue


# ------------------------------------------------------------------ return
def return_line(db: Session, actor: User, line_id: int, data: ReturnIn) -> IssueLine:
    t = today()
    line = db.get(IssueLine, line_id)
    if line is None:
        raise BusinessError("Issue line not found.", 404)
    if line.status != LineStatus.OPEN:
        raise BusinessError("This line has already been fully returned.")
    if data.quantity > line.outstanding:
        raise BusinessError(f"Only {line.outstanding} {plural(line.outstanding, 'unit')} outstanding; cannot accept {data.quantity}.")
    rdate = data.return_date or t
    if rdate > t:
        raise BusinessError("The return date cannot be in the future.", 422)
    if rdate < line.issue.issue_date:
        raise BusinessError("The return date cannot be before the issue date.", 422)

    cond = data.condition
    if line.asset_id:
        asset = db.get(Asset, line.asset_id)
        asset.status = _COND_TO_STATUS[cond]  # unavailable unless GOOD/FAIR, until coordinator updates it (rule 10)
        asset.condition = cond
    else:
        col = _COL[_COND_TO_BUCKET[cond]]
        res = db.execute(update(Item).where(Item.id == line.item_id, Item.qty_issued >= data.quantity)
                         .values(qty_issued=Item.qty_issued - data.quantity, **{col: getattr(Item, col) + data.quantity}))
        if res.rowcount != 1:
            raise BusinessError("Stock records are inconsistent for this item; contact the administrator.", 500)
    line.qty_returned += data.quantity
    if line.outstanding == 0:
        line.status = LineStatus.CLOSED
        for r in db.scalars(select(Renewal).where(Renewal.line_id == line.id, Renewal.status == RenewalStatus.PENDING)):
            r.status, r.decided_on, r.decided_by_id = RenewalStatus.REJECTED, t, actor.id
            r.remarks = "Closed automatically: items were returned."
    db.add(ReturnRecord(line_id=line.id, quantity=data.quantity, condition=cond, returned_on=rdate, received_by_id=actor.id, remarks=data.remarks))
    audit(db, actor, "RETURN", "issue_line", line.id, {"qty": data.quantity, "condition": cond.value, "outstanding": line.outstanding})
    db.commit()
    return line


# ------------------------------------------------------------------ renewals
def request_renewal(db: Session, user: User, data: RenewalRequestIn) -> Renewal:
    t = today()
    line = db.get(IssueLine, data.line_id)
    if line is None or line.issue.student_id != user.student_id:  # same answer for "not yours" and "doesn't exist" (no IDOR probing)
        raise BusinessError("Issued item not found.", 404)
    if line.status != LineStatus.OPEN:
        raise BusinessError("This item has already been returned.")
    if t > line.due_date:
        raise BusinessError("The due date has passed; renewal can no longer be requested. Please return the item or contact the coordinator.")
    pol = get_policy(db)
    if line.renewal_count >= pol.max_renewals_per_line:
        raise BusinessError(f"Renewal limit reached ({pol.max_renewals_per_line} per item). Please return the item.")
    if db.scalar(select(Renewal.id).where(Renewal.line_id == line.id, Renewal.status == RenewalStatus.PENDING)):
        raise BusinessError("A renewal request for this item is already pending.")
    r = Renewal(line_id=line.id, requested_by_id=user.id, requested_on=t, reason=data.reason)
    db.add(r)
    db.flush()
    audit(db, user, "RENEWAL_REQUEST", "renewal", r.id, {"line_id": line.id})  # due date deliberately NOT changed (rule 7)
    db.commit()
    return r


def decide_renewal(db: Session, actor: User, renewal_id: int, data: RenewalDecisionIn) -> Renewal:
    t = today()
    r = db.get(Renewal, renewal_id)
    if r is None:
        raise BusinessError("Renewal request not found.", 404)
    if r.status != RenewalStatus.PENDING:
        raise BusinessError(f"This request was already {r.status.value.lower()}.")
    line = r.line
    if line.status != LineStatus.OPEN:
        raise BusinessError("The item has already been returned; nothing to renew.")
    if not data.approve:
        if not data.remarks:
            raise BusinessError("Remarks are required when rejecting a renewal.", 422)
        r.status = RenewalStatus.REJECTED
    else:
        pol = get_policy(db)
        if line.renewal_count >= pol.max_renewals_per_line:
            raise BusinessError(f"Renewal limit reached ({pol.max_renewals_per_line} per item).")
        r.previous_due = line.due_date
        line.due_date = line.due_date + timedelta(days=ISSUE_PERIOD_DAYS)  # rule 8: +15 days from the EXISTING due date
        line.renewal_count += 1
        r.revised_due = line.due_date
        r.status = RenewalStatus.APPROVED
    r.decided_by_id, r.decided_on, r.remarks = actor.id, t, data.remarks
    audit(db, actor, "RENEWAL_" + r.status.value, "renewal", r.id, {"line_id": line.id, "revised_due": r.revised_due})
    db.commit()
    return r


# ------------------------------------------------------------------ inventory
def create_item(db: Session, actor: User, data: ItemIn) -> Item:
    if data.kind == ItemKind.ASSET and data.initial_quantity:
        raise BusinessError("Individually tracked items get their stock by registering each asset (POST /items/{id}/assets).", 422)
    if db.scalar(select(Item.id).where(Item.code == data.code)):
        raise BusinessError("An item with this code already exists.")
    q = data.initial_quantity
    item = Item(code=data.code, name=data.name, category=data.category, description=data.description, make_model=data.make_model,
                kind=data.kind, location_id=data.location_id, max_issue_qty=data.max_issue_qty, qty_total=q, qty_available=q)
    db.add(item)
    db.flush()
    if q:
        db.add(StockAdjustment(item_id=item.id, action="ADD", to_bucket="AVAILABLE", quantity=q, reason="Initial stock", by_id=actor.id, adjusted_on=today()))
    audit(db, actor, "ITEM_CREATE", "item", item.id, {"code": item.code, "kind": item.kind.value, "qty": q})
    db.commit()
    return item


def add_asset(db: Session, actor: User, item: Item, data: AssetIn) -> Asset:
    if item.kind != ItemKind.ASSET or not item.is_active:
        raise BusinessError("Assets can only be added to active, individually tracked items.", 422)
    if db.scalar(select(Asset.id).where(Asset.asset_tag == data.asset_tag)):
        raise BusinessError("An asset with this ID already exists.")
    a = Asset(asset_tag=data.asset_tag, item_id=item.id, serial_no=data.serial_no, location_id=data.location_id or item.location_id,
              condition=data.condition, status=_COND_TO_STATUS[data.condition])
    db.add(a)
    db.flush()
    db.add(StockAdjustment(item_id=item.id, asset_id=a.id, action="ADD", to_bucket=a.status.value, quantity=1, reason="New asset registered", by_id=actor.id, adjusted_on=today()))
    audit(db, actor, "ASSET_CREATE", "asset", a.id, {"tag": a.asset_tag, "item_id": item.id})
    db.commit()
    return a


def set_asset_status(db: Session, actor: User, asset: Asset, data: AssetStatusIn) -> Asset:
    if asset.status == AssetStatus.ISSUED:
        raise BusinessError("This asset is currently issued; record its return first.")
    if asset.status == AssetStatus.RETIRED:
        raise BusinessError("A retired asset cannot be changed.")
    if data.status == AssetStatus.ISSUED:
        raise BusinessError("Assets become ISSUED only through the issue process.", 422)
    new_cond = data.condition
    if data.status == AssetStatus.AVAILABLE:
        new_cond = new_cond or Condition.GOOD
        if new_cond not in USABLE_CONDITIONS:
            raise BusinessError("An asset can be made available only in GOOD or FAIR condition.", 422)
    elif data.status == AssetStatus.DAMAGED:
        new_cond = new_cond or Condition.DAMAGED
    elif data.status == AssetStatus.MAINTENANCE:
        new_cond = new_cond or Condition.NEEDS_MAINTENANCE
    elif data.status == AssetStatus.LOST:
        new_cond = new_cond or Condition.LOST
    old = asset.status
    asset.status, asset.condition = data.status, new_cond or asset.condition
    db.add(StockAdjustment(item_id=asset.item_id, asset_id=asset.id, action="RETIRE" if data.status == AssetStatus.RETIRED else "STATUS_CHANGE",
                           from_bucket=old.value, to_bucket=data.status.value, quantity=1, reason=data.reason, by_id=actor.id, adjusted_on=today()))
    audit(db, actor, "ASSET_STATUS", "asset", asset.id, {"from": old.value, "to": data.status.value})
    db.commit()
    return asset


def adjust_item(db: Session, actor: User, item: Item, d: AdjustIn) -> Item:
    if item.kind != ItemKind.QUANTITY:
        raise BusinessError("Use the asset endpoints for individually tracked items.", 422)
    if not item.is_active:
        raise BusinessError("This item has been retired.")
    src = _COL[d.bucket]
    q = d.quantity

    def need_positive():
        if q < 1:
            raise BusinessError("Quantity must be at least 1 for this action.", 422)

    def take(col: str, n: int, total_delta: int, give: str | None = None):
        vals = {col: getattr(Item, col) - n, "qty_total": Item.qty_total + total_delta}
        if give:
            vals[give] = getattr(Item, give) + n
        res = db.execute(update(Item).where(Item.id == item.id, getattr(Item, col) >= n).values(**vals))
        if res.rowcount != 1:
            db.refresh(item)
            raise BusinessError(f"Cannot remove {n}: only {getattr(item, col)} currently in {col.removeprefix('qty_')}. (Issued items must be returned first.)")

    if d.action == AdjustAction.ADD:
        need_positive()
        if d.bucket != Bucket.AVAILABLE:
            raise BusinessError("New stock is always added as AVAILABLE.", 422)
        db.execute(update(Item).where(Item.id == item.id).values(qty_available=Item.qty_available + q, qty_total=Item.qty_total + q))
    elif d.action == AdjustAction.MOVE:
        need_positive()
        if d.to_bucket is None or d.to_bucket == d.bucket:
            raise BusinessError("MOVE needs a different to_bucket.", 422)
        take(src, q, 0, give=_COL[d.to_bucket])
    elif d.action == AdjustAction.RETIRE:
        need_positive()
        take(src, q, -q)
    else:  # CORRECT: signed fix to a miscount
        if q == 0:
            raise BusinessError("A correction cannot be zero.", 422)
        if q > 0:
            db.execute(update(Item).where(Item.id == item.id).values(**{src: getattr(Item, src) + q, "qty_total": Item.qty_total + q}))
        else:
            take(src, -q, q)
    db.add(StockAdjustment(item_id=item.id, action=d.action.value, from_bucket=d.bucket.value, to_bucket=d.to_bucket.value if d.to_bucket else None,
                           quantity=q, reason=d.reason, by_id=actor.id, adjusted_on=today()))
    audit(db, actor, "STOCK_" + d.action.value, "item", item.id, {"bucket": d.bucket.value, "to": d.to_bucket.value if d.to_bucket else None, "qty": q})
    db.commit()
    db.refresh(item)
    return item


# ------------------------------------------------------------------ stock summary
def stock_summary(db: Session, item_id: int | None = None, location_id: int | None = None) -> list[dict]:
    t = today()
    q = select(Item).order_by(Item.code)
    if item_id:
        q = q.where(Item.id == item_id)
    if location_id:
        q = q.where(Item.location_id == location_id)
    items = list(db.scalars(q))
    ids = [i.id for i in items]
    assets: dict[tuple[int, AssetStatus], int] = {}
    for iid, st, n in db.execute(select(Asset.item_id, Asset.status, func.count()).where(Asset.item_id.in_(ids)).group_by(Asset.item_id, Asset.status)):
        assets[(iid, st)] = n
    over = dict(db.execute(select(IssueLine.item_id, func.sum(IssueLine.qty_issued - IssueLine.qty_returned))
                           .where(IssueLine.status == LineStatus.OPEN, IssueLine.due_date < t, IssueLine.item_id.in_(ids)).group_by(IssueLine.item_id)).all())
    rows = []
    for i in items:
        if i.kind == ItemKind.QUANTITY:
            r = dict(total=i.qty_total, available=i.qty_available, issued=i.qty_issued, damaged=i.qty_damaged, lost=i.qty_lost, maintenance=i.qty_maintenance)
        else:
            g = lambda s: assets.get((i.id, s), 0)  # noqa: E731
            r = dict(total=sum(v for (iid, st), v in assets.items() if iid == i.id and st != AssetStatus.RETIRED), available=g(AssetStatus.AVAILABLE),
                     issued=g(AssetStatus.ISSUED), damaged=g(AssetStatus.DAMAGED), lost=g(AssetStatus.LOST), maintenance=g(AssetStatus.MAINTENANCE))
        rows.append({"item_id": i.id, "code": i.code, "name": i.name, "kind": i.kind.value, "category": i.category, "active": i.is_active,
                     **r, "overdue": int(over.get(i.id, 0))})
    return rows
