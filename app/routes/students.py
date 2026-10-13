from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import audit
from ..db import get_db
from ..deps import coordinator, staff_any
from ..models import Role, Student, User
from ..schemas import PathId, QueryId, StudentCreated, StudentIn, StudentOut, StudentPatchIn
from ..security import blind_index, generate_temp_password, hash_password

router = APIRouter(prefix="/students", tags=["students"])


@router.post("", response_model=StudentCreated, status_code=201)
def create_student(body: StudentIn, user: User = Depends(coordinator), db: Session = Depends(get_db)):
    idx = blind_index(body.enrolment_no)
    username = body.enrolment_no.lower()
    if db.scalar(select(Student.id).where(Student.enrolment_idx == idx)) or db.scalar(select(User.id).where(User.username == username)):
        raise HTTPException(409, "A student with this enrolment number already exists")
    s = Student(enrolment_no=body.enrolment_no.upper(), enrolment_idx=idx, name=body.name, programme=body.programme,
                semester=body.semester, email=body.email, phone=body.phone)
    db.add(s)
    db.flush()
    pw = generate_temp_password()
    db.add(User(username=username, password_hash=hash_password(pw), role=Role.STUDENT, student_id=s.id, must_change_password=True))
    audit(db, user, "STUDENT_CREATE", "student", s.id)
    db.commit()
    return {"student": s, "username": username, "temporary_password": pw}


@router.get("", response_model=list[StudentOut])
def list_students(user: User = Depends(staff_any), db: Session = Depends(get_db), programme: str | None = Query(None, max_length=80),
                  semester: int | None = Query(None, ge=1, le=12), enrolment_no: str | None = Query(None, max_length=20, pattern=r"^[A-Za-z0-9]+$"),
                  limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    q = select(Student).order_by(Student.id).limit(limit).offset(offset)
    if programme:
        q = q.where(Student.programme == programme)
    if semester:
        q = q.where(Student.semester == semester)
    if enrolment_no:  # exact lookup through the blind index (the column itself is encrypted)
        q = q.where(Student.enrolment_idx == blind_index(enrolment_no))
    return db.scalars(q).all()


@router.get("/{student_id}", response_model=StudentOut)
def get_student(student_id: PathId, user: User = Depends(staff_any), db: Session = Depends(get_db)):
    s = db.get(Student, student_id)
    if s is None:
        raise HTTPException(404, "Student not found")
    return s


@router.patch("/{student_id}", response_model=StudentOut)
def patch_student(student_id: PathId, body: StudentPatchIn, user: User = Depends(coordinator), db: Session = Depends(get_db)):
    s = db.get(Student, student_id)
    if s is None:
        raise HTTPException(404, "Student not found")
    data = body.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(s, k, v)
    if "is_active" in data and data["is_active"] is not None:  # deactivation kills the login immediately
        u = db.scalar(select(User).where(User.student_id == s.id))
        if u:
            u.is_active = data["is_active"]
            if not u.is_active:
                u.token_version += 1
    audit(db, user, "STUDENT_UPDATE", "student", s.id, {"fields": sorted(data)})
    db.commit()
    return s
