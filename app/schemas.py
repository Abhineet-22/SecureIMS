"""Every input is validated: strict types, length caps, character allow-lists, unknown fields rejected."""
import re
from datetime import date, datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints, field_validator

from .models import (AdjustAction, AssetStatus, Bucket, Condition, ItemKind, LineStatus, LocationKind,
                     RenewalStatus, Role)

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

Code = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,39}$")]
Enrolment = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9]{5,20}$")]
Username = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_.\-]{2,63}$")]
Phone = Annotated[str, StringConstraints(pattern=r"^\+?[0-9]{7,15}$")]
Name80 = Annotated[str, StringConstraints(min_length=1, max_length=80)]
Name120 = Annotated[str, StringConstraints(min_length=1, max_length=120)]
Text300 = Annotated[str, StringConstraints(min_length=3, max_length=300)]
Text500 = Annotated[str, StringConstraints(max_length=500)]
Text1000 = Annotated[str, StringConstraints(max_length=1000)]
Qty = Annotated[int, Field(ge=1, le=100_000)]
Id = Annotated[int, Field(ge=1, le=2**31 - 1)]


class In(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @field_validator("*", mode="after")
    @classmethod
    def _no_control_chars(cls, v):
        if isinstance(v, str) and _CTRL.search(v):
            raise ValueError("control characters are not allowed")
        return v


class Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---- auth
class LoginIn(In):
    username: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    password: Annotated[str, StringConstraints(min_length=1, max_length=128, strip_whitespace=False)]


class RefreshIn(In):
    refresh_token: Annotated[str, StringConstraints(min_length=20, max_length=200)]


class LogoutIn(RefreshIn):
    all_devices: bool = False


class ChangePasswordIn(In):
    old_password: Annotated[str, StringConstraints(min_length=1, max_length=128, strip_whitespace=False)]
    new_password: Annotated[str, StringConstraints(min_length=1, max_length=128, strip_whitespace=False)]


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    must_change_password: bool


class UserOut(Out):
    id: int
    username: str
    role: Role
    student_id: int | None
    is_active: bool
    must_change_password: bool


class UserCreateIn(In):
    username: Username
    role: Role
    password: str | None = Field(default=None, max_length=128)  # omitted => random temp password


class UserPatchIn(In):
    is_active: bool | None = None
    unlock: bool | None = None


class TempCredential(BaseModel):
    user: UserOut
    temporary_password: str  # shown ONCE; the user must change it at first login


# ---- students / locations
class StudentIn(In):
    enrolment_no: Enrolment
    name: Name120
    programme: Name80
    semester: Annotated[int, Field(ge=1, le=12)]
    email: EmailStr
    phone: Phone | None = None


class StudentPatchIn(In):
    name: Name120 | None = None
    programme: Name80 | None = None
    semester: Annotated[int, Field(ge=1, le=12)] | None = None
    email: EmailStr | None = None
    phone: Phone | None = None
    is_active: bool | None = None


class StudentOut(Out):
    id: int
    enrolment_no: str
    name: str
    programme: str
    semester: int
    email: str
    phone: str | None
    is_active: bool


class StudentCreated(BaseModel):
    student: StudentOut
    username: str
    temporary_password: str


class LocationIn(In):
    name: Name120
    kind: LocationKind
    description: Text500 | None = None


class LocationOut(Out):
    id: int
    name: str
    kind: LocationKind
    description: str | None


# ---- inventory
class ItemIn(In):
    code: Code
    name: Name120
    category: Name80
    description: Text1000 | None = None
    make_model: Annotated[str, StringConstraints(max_length=120)] | None = None
    kind: ItemKind
    location_id: Id | None = None
    max_issue_qty: Qty | None = None
    initial_quantity: Annotated[int, Field(ge=0, le=100_000)] = 0  # QUANTITY items only


class ItemPatchIn(In):
    name: Name120 | None = None
    category: Name80 | None = None
    description: Text1000 | None = None
    make_model: Annotated[str, StringConstraints(max_length=120)] | None = None
    location_id: Id | None = None
    max_issue_qty: Qty | None = None


class ItemOut(Out):
    id: int
    code: str
    name: str
    category: str
    description: str | None
    make_model: str | None
    kind: ItemKind
    location_id: int | None
    max_issue_qty: int | None
    is_active: bool


class AssetIn(In):
    asset_tag: Code
    serial_no: Annotated[str, StringConstraints(max_length=80)] | None = None
    location_id: Id | None = None
    condition: Condition = Condition.GOOD


class AssetStatusIn(In):
    status: AssetStatus
    condition: Condition | None = None
    reason: Text300


class AssetOut(Out):
    id: int
    asset_tag: str
    item_id: int
    serial_no: str | None
    location_id: int | None
    condition: Condition
    status: AssetStatus


class AdjustIn(In):
    action: AdjustAction
    bucket: Bucket = Bucket.AVAILABLE      # source bucket (or target for ADD / CORRECT)
    to_bucket: Bucket | None = None        # MOVE only
    quantity: Annotated[int, Field(ge=-100_000, le=100_000)]
    reason: Text300


class PolicyIn(In):
    max_open_lines_per_student: Annotated[int, Field(ge=1, le=100)] | None = None
    max_renewals_per_line: Annotated[int, Field(ge=0, le=20)] | None = None
    block_issue_if_overdue: bool | None = None
    max_backdate_days: Annotated[int, Field(ge=0, le=365)] | None = None


class PolicyOut(Out):
    max_open_lines_per_student: int
    max_renewals_per_line: int
    block_issue_if_overdue: bool
    max_backdate_days: int


# ---- transactions
class IssueLineIn(In):
    item_id: Id
    asset_id: Id | None = None
    quantity: Qty = 1


class IssueIn(In):
    student_id: Id
    purpose: Text300
    issue_date: date | None = None
    lines: Annotated[list[IssueLineIn], Field(min_length=1, max_length=20)]


class ReturnIn(In):
    quantity: Qty = 1
    condition: Condition
    remarks: Text500 | None = None
    return_date: date | None = None


class RenewalRequestIn(In):
    line_id: Id
    reason: Text300 | None = None


class RenewalDecisionIn(In):
    approve: bool
    remarks: Text300 | None = None


class LineOut(BaseModel):
    line_id: int
    item_code: str
    item_name: str
    asset_tag: str | None
    quantity_issued: int
    quantity_returned: int
    outstanding: int
    due_date: date
    renewals_used: int
    status: LineStatus
    overdue: bool
    overdue_days: int
    pending_renewal: bool


class AckOut(BaseModel):
    ack_no: str
    issue_id: int
    student_name: str
    enrolment_no: str
    programme: str
    purpose: str
    issue_date: date
    issued_by: str
    lines: list[LineOut]
    note: str


class RenewalOut(BaseModel):
    id: int
    line_id: int
    item_name: str
    asset_tag: str | None
    student_id: int | None = None
    requested_on: date
    reason: str | None
    status: RenewalStatus
    decided_on: date | None
    remarks: str | None
    previous_due: date | None
    revised_due: date | None


# ---- bounded ids for path/query parameters (a huge integer must be a 422, never a DB overflow / 500)
from fastapi import Path, Query  # noqa: E402

_MAX = 2**31 - 1
PathId = Annotated[int, Path(ge=1, le=_MAX)]
QueryId = Annotated[int | None, Query(ge=1, le=_MAX)]
