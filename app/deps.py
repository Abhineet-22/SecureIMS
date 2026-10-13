from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .audit import audit
from .db import get_db
from .models import Role, User
from .security import decode_access_token

_bearer = HTTPBearer(auto_error=False)
_UNAUTH = HTTPException(401, "Not authenticated", headers={"WWW-Authenticate": "Bearer"})


def _load_user(creds: HTTPAuthorizationCredentials | None, db: Session) -> User:
    if creds is None:
        raise _UNAUTH
    claims = decode_access_token(creds.credentials)
    if claims is None:
        raise _UNAUTH
    try:
        user = db.get(User, int(claims["sub"]))
    except (ValueError, TypeError):
        raise _UNAUTH from None
    # Role comes from the DB, never from the token. token_version lets us revoke every token instantly.
    if user is None or not user.is_active or user.token_version != claims["ver"]:
        raise _UNAUTH
    return user


def current_user_allow_pw_change(creds=Depends(_bearer), db: Session = Depends(get_db)) -> User:
    return _load_user(creds, db)


def current_user(user: User = Depends(current_user_allow_pw_change)) -> User:
    if user.must_change_password:
        raise HTTPException(403, "You must change your temporary password first (POST /auth/change-password).")
    return user


def require(*roles: Role):
    allowed = set(roles) | {Role.ADMIN}

    def dep(user: User = Depends(current_user), db: Session = Depends(get_db)) -> User:
        if user.role not in allowed:
            audit(db, user, "ACCESS_DENIED", "route", detail={"needed": sorted(r.value for r in allowed)})
            db.commit()
            raise HTTPException(403, "You do not have permission to perform this action.")
        return user
    return dep


staff_any = require(Role.COORDINATOR, Role.STAFF)       # issue / return / view
coordinator = require(Role.COORDINATOR)                 # manage inventory, approve renewals, policy
admin_only = require(Role.ADMIN)



def student_user(user: User = Depends(current_user)) -> User:
    if user.role != Role.STUDENT or user.student_id is None:
        raise HTTPException(403, "Student account required.")
    return user
