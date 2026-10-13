from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..audit import audit, verify_chain
from ..db import get_db
from ..deps import admin_only
from ..models import AuditLog, RefreshToken, Role, User
from ..schemas import PathId, QueryId, TempCredential, UserCreateIn, UserOut, UserPatchIn
from ..security import generate_temp_password, hash_password, password_problems

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/users", response_model=TempCredential, status_code=201)
def create_staff(body: UserCreateIn, admin: User = Depends(admin_only), db: Session = Depends(get_db)):
    if body.role == Role.STUDENT:
        raise HTTPException(422, "Student logins are created together with the student record (POST /students).")
    pw = body.password or generate_temp_password()
    if body.password and (p := password_problems(pw, body.username)):
        raise HTTPException(422, "Password " + "; ".join(p))
    u = User(username=body.username, password_hash=hash_password(pw), role=body.role, must_change_password=True)
    db.add(u)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Username already exists") from None
    audit(db, admin, "USER_CREATE", "user", u.id, {"role": body.role.value})
    db.commit()
    return {"user": u, "temporary_password": pw}


@router.get("/users", response_model=list[UserOut])
def list_users(admin: User = Depends(admin_only), db: Session = Depends(get_db), limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    return db.scalars(select(User).order_by(User.id).limit(limit).offset(offset)).all()


@router.patch("/users/{user_id}", response_model=UserOut)
def patch_user(user_id: PathId, body: UserPatchIn, admin: User = Depends(admin_only), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "User not found")
    if body.is_active is not None:
        if u.id == admin.id and not body.is_active:
            raise HTTPException(409, "You cannot disable your own account")
        u.is_active = body.is_active
        if not body.is_active:
            u.token_version += 1
            db.execute(update(RefreshToken).where(RefreshToken.user_id == u.id).values(revoked=True))
    if body.unlock:
        u.locked_until, u.failed_attempts = None, 0
    audit(db, admin, "USER_UPDATE", "user", u.id, body.model_dump(exclude_none=True))
    db.commit()
    return u


@router.post("/users/{user_id}/reset-password", response_model=TempCredential)
def reset_password(user_id: PathId, admin: User = Depends(admin_only), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "User not found")
    pw = generate_temp_password()
    u.password_hash, u.must_change_password, u.token_version = hash_password(pw), True, u.token_version + 1
    u.locked_until, u.failed_attempts = None, 0
    db.execute(update(RefreshToken).where(RefreshToken.user_id == u.id).values(revoked=True))
    audit(db, admin, "PASSWORD_RESET", "user", u.id)
    db.commit()
    return {"user": u, "temporary_password": pw}


@router.get("/audit")
def audit_log(admin: User = Depends(admin_only), db: Session = Depends(get_db), action: str | None = Query(None, max_length=64),
              limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    q = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit).offset(offset)
    if action:
        q = q.where(AuditLog.action == action)
    return [{"id": r.id, "ts": r.ts, "actor_id": r.actor_id, "role": r.actor_role, "action": r.action, "entity": r.entity,
             "entity_id": r.entity_id, "detail": r.detail, "ip": r.ip, "hash": r.hash} for r in db.scalars(q)]


@router.get("/audit/verify")
def audit_verify(admin: User = Depends(admin_only), db: Session = Depends(get_db)):
    return verify_chain(db)
