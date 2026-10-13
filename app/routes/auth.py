from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..audit import audit
from ..clock import utcnow
from ..config import get_settings
from ..db import get_db
from ..deps import current_user_allow_pw_change
from ..models import RefreshToken, User
from ..ratelimit import limit
from ..schemas import ChangePasswordIn, LoginIn, LogoutIn, RefreshIn, TokenOut, UserOut
from ..security import (create_access_token, dummy_hash, hash_password, hash_refresh_token, needs_rehash,
                        new_refresh_token, password_problems, verify_password)

router = APIRouter(prefix="/auth", tags=["auth"])
_BAD = HTTPException(401, "Invalid credentials")  # one message for: unknown user / wrong password / locked / disabled


def _tokens(db: Session, user: User) -> TokenOut:
    access, ttl = create_access_token(user.id, user.role.value, user.token_version)
    raw, h = new_refresh_token()
    db.add(RefreshToken(user_id=user.id, token_hash=h, expires_at=utcnow() + timedelta(days=get_settings().refresh_token_days)))
    return TokenOut(access_token=access, refresh_token=raw, expires_in=ttl, must_change_password=user.must_change_password)


@router.post("/login", response_model=TokenOut, dependencies=[Depends(limit("login", setting="login_rate_per_min"))])
def login(body: LoginIn, db: Session = Depends(get_db)):
    s = get_settings()
    user = db.scalar(select(User).where(User.username == body.username.strip().lower()))
    # Always run one Argon2 verification -> response time doesn't reveal whether the user exists / is locked.
    ok = verify_password(user.password_hash if user else dummy_hash(), body.password)
    now = utcnow()
    if user is None:
        audit(db, None, "LOGIN_FAIL", "user", None, {"reason": "unknown_user"})
        db.commit()
        raise _BAD
    if user.locked_until and user.locked_until > now:
        audit(db, user, "LOGIN_BLOCKED_LOCKED", "user", user.id)
        db.commit()
        raise _BAD
    if not ok or not user.is_active:
        user.failed_attempts += 1
        if user.failed_attempts >= s.login_max_failures:
            user.locked_until, user.failed_attempts = now + timedelta(minutes=s.lockout_minutes), 0
            audit(db, user, "ACCOUNT_LOCKED", "user", user.id)
        audit(db, user, "LOGIN_FAIL", "user", user.id)
        db.commit()
        raise _BAD
    user.failed_attempts, user.locked_until = 0, None
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    out = _tokens(db, user)
    audit(db, user, "LOGIN_OK", "user", user.id)
    db.commit()
    return out


@router.post("/refresh", response_model=TokenOut, dependencies=[Depends(limit("refresh", 30))])
def refresh(body: RefreshIn, db: Session = Depends(get_db)):
    rt = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(body.refresh_token)))
    if rt is None:
        raise _BAD
    user = db.get(User, rt.user_id)
    if rt.revoked:
        # A rotated token was replayed => likely stolen. Kill every session of this user.
        user.token_version += 1
        db.execute(update(RefreshToken).where(RefreshToken.user_id == user.id).values(revoked=True))
        audit(db, user, "REFRESH_REUSE_DETECTED", "user", user.id)
        db.commit()
        raise _BAD
    if rt.expires_at < utcnow() or not user.is_active:
        raise _BAD
    rt.revoked = True  # rotation: one-time use
    out = _tokens(db, user)
    db.commit()
    return out


@router.post("/logout", status_code=204)
def logout(body: LogoutIn, user: User = Depends(current_user_allow_pw_change), db: Session = Depends(get_db)):
    rt = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(body.refresh_token), RefreshToken.user_id == user.id))
    if rt:
        rt.revoked = True
    if body.all_devices:
        user.token_version += 1
        db.execute(update(RefreshToken).where(RefreshToken.user_id == user.id).values(revoked=True))
    audit(db, user, "LOGOUT", "user", user.id, {"all": body.all_devices})
    db.commit()
    return Response(status_code=204)


@router.post("/change-password", status_code=204, dependencies=[Depends(limit("pwchange", 5))])
def change_password(body: ChangePasswordIn, user: User = Depends(current_user_allow_pw_change), db: Session = Depends(get_db)):
    if not verify_password(user.password_hash, body.old_password):
        audit(db, user, "PASSWORD_CHANGE_FAIL", "user", user.id)
        db.commit()
        raise HTTPException(400, "Old password is incorrect")
    problems = password_problems(body.new_password, user.username)
    if body.new_password == body.old_password:
        problems.append("must differ from the old password")
    if problems:
        raise HTTPException(422, "New password " + "; ".join(problems))
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    user.token_version += 1  # every existing access token dies now
    db.execute(update(RefreshToken).where(RefreshToken.user_id == user.id).values(revoked=True))
    audit(db, user, "PASSWORD_CHANGED", "user", user.id)
    db.commit()
    return Response(status_code=204)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user_allow_pw_change)):
    return user
