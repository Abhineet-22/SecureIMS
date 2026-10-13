import enum
from datetime import date, datetime

import sqlalchemy as sa
from sqlalchemy import CheckConstraint, ForeignKey, Index, String, event
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .clock import utcnow
from .db import Base
from .security import decrypt_field, encrypt_field


class EncryptedText(sa.TypeDecorator):
    """Transparent AES-256-GCM column. `aad` ties ciphertext to its table.column (no copy/paste attacks)."""
    impl = sa.Text
    cache_ok = True

    def __init__(self, aad: str):
        super().__init__()
        self.aad = aad

    def process_bind_param(self, value, dialect):
        return None if value is None else encrypt_field(value, self.aad)

    def process_result_value(self, value, dialect):
        return None if value is None else decrypt_field(value, self.aad)


def E(py_enum):  # enum stored as VARCHAR + DB CHECK constraint
    return sa.Enum(py_enum, native_enum=False, create_constraint=True, length=24, validate_strings=True)


class Role(str, enum.Enum):
    ADMIN = "ADMIN"
    COORDINATOR = "COORDINATOR"
    STAFF = "STAFF"
    STUDENT = "STUDENT"


class ItemKind(str, enum.Enum):
    ASSET = "ASSET"          # individually tracked (laptops, dev boards)
    QUANTITY = "QUANTITY"    # counted (cables, adapters)


class AssetStatus(str, enum.Enum):
    AVAILABLE = "AVAILABLE"
    ISSUED = "ISSUED"
    DAMAGED = "DAMAGED"
    LOST = "LOST"
    MAINTENANCE = "MAINTENANCE"
    RETIRED = "RETIRED"


class Condition(str, enum.Enum):
    GOOD = "GOOD"
    FAIR = "FAIR"
    DAMAGED = "DAMAGED"
    NEEDS_MAINTENANCE = "NEEDS_MAINTENANCE"
    LOST = "LOST"


USABLE_CONDITIONS = {Condition.GOOD, Condition.FAIR}


class LocationKind(str, enum.Enum):
    DEPARTMENT = "DEPARTMENT"
    LABORATORY = "LABORATORY"
    ROOM = "ROOM"
    CUPBOARD = "CUPBOARD"
    OTHER = "OTHER"


class LineStatus(str, enum.Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"


class RenewalStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class AdjustAction(str, enum.Enum):
    ADD = "ADD"
    MOVE = "MOVE"
    RETIRE = "RETIRE"
    CORRECT = "CORRECT"


class Bucket(str, enum.Enum):
    AVAILABLE = "AVAILABLE"
    DAMAGED = "DAMAGED"
    LOST = "LOST"
    MAINTENANCE = "MAINTENANCE"


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(E(Role))
    student_id: Mapped[int | None] = mapped_column(ForeignKey("students.id"), unique=True)
    is_active: Mapped[bool] = mapped_column(default=True)
    must_change_password: Mapped[bool] = mapped_column(default=True)
    failed_attempts: Mapped[int] = mapped_column(default=0)
    locked_until: Mapped[datetime | None]
    token_version: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    __table_args__ = (CheckConstraint("(role = 'STUDENT') = (student_id IS NOT NULL)", name="ck_student_link"),)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)  # only the SHA-256 is stored
    expires_at: Mapped[datetime]
    revoked: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class Student(Base):
    __tablename__ = "students"
    id: Mapped[int] = mapped_column(primary_key=True)
    enrolment_no: Mapped[str] = mapped_column(EncryptedText("students.enrolment_no"))
    enrolment_idx: Mapped[str] = mapped_column(String(64), unique=True)  # HMAC blind index
    name: Mapped[str] = mapped_column(EncryptedText("students.name"))
    programme: Mapped[str] = mapped_column(String(80), index=True)
    semester: Mapped[int]
    email: Mapped[str] = mapped_column(EncryptedText("students.email"))
    phone: Mapped[str | None] = mapped_column(EncryptedText("students.phone"))
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class Location(Base):
    __tablename__ = "locations"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    kind: Mapped[LocationKind] = mapped_column(E(LocationKind))
    description: Mapped[str | None] = mapped_column(String(500))


class Item(Base):
    __tablename__ = "items"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120))
    category: Mapped[str] = mapped_column(String(80), index=True)
    description: Mapped[str | None] = mapped_column(String(1000))
    make_model: Mapped[str | None] = mapped_column(String(120))
    kind: Mapped[ItemKind] = mapped_column(E(ItemKind))
    location_id: Mapped[int | None] = mapped_column(ForeignKey("locations.id"))
    max_issue_qty: Mapped[int | None]  # per-item policy limit
    # Counters are used only for QUANTITY items (ASSET items are counted from the assets table)
    qty_total: Mapped[int] = mapped_column(default=0)
    qty_available: Mapped[int] = mapped_column(default=0)
    qty_issued: Mapped[int] = mapped_column(default=0)
    qty_damaged: Mapped[int] = mapped_column(default=0)
    qty_lost: Mapped[int] = mapped_column(default=0)
    qty_maintenance: Mapped[int] = mapped_column(default=0)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    location = relationship("Location")
    __table_args__ = (
        # Stock can never go negative and the books always balance -- enforced by the DATABASE.
        CheckConstraint("qty_available>=0 AND qty_issued>=0 AND qty_damaged>=0 AND qty_lost>=0 AND qty_maintenance>=0", name="ck_qty_nonneg"),
        CheckConstraint(
            "(kind='QUANTITY' AND qty_total=qty_available+qty_issued+qty_damaged+qty_lost+qty_maintenance)"
            " OR (kind='ASSET' AND qty_total=0 AND qty_available=0 AND qty_issued=0 AND qty_damaged=0 AND qty_lost=0 AND qty_maintenance=0)",
            name="ck_qty_balance"),
        CheckConstraint("max_issue_qty IS NULL OR max_issue_qty>0", name="ck_max_issue"),
    )


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_tag: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    item_id: Mapped[int] = mapped_column(ForeignKey("items.id"), index=True)
    serial_no: Mapped[str | None] = mapped_column(String(80))
    location_id: Mapped[int | None] = mapped_column(ForeignKey("locations.id"))
    condition: Mapped[Condition] = mapped_column(E(Condition), default=Condition.GOOD)
    status: Mapped[AssetStatus] = mapped_column(E(AssetStatus), default=AssetStatus.AVAILABLE)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    item = relationship("Item")
    location = relationship("Location")


class Policy(Base):
    __tablename__ = "policy"
    id: Mapped[int] = mapped_column(primary_key=True)
    max_open_lines_per_student: Mapped[int] = mapped_column(default=6)
    max_renewals_per_line: Mapped[int] = mapped_column(default=2)
    block_issue_if_overdue: Mapped[bool] = mapped_column(default=True)
    max_backdate_days: Mapped[int] = mapped_column(default=30)
    __table_args__ = (CheckConstraint("id=1", name="ck_policy_singleton"),)


class Issue(Base):
    __tablename__ = "issues"
    id: Mapped[int] = mapped_column(primary_key=True)
    ack_no: Mapped[str] = mapped_column(String(32), unique=True)
    student_id: Mapped[int] = mapped_column(ForeignKey("students.id"), index=True)
    issued_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    issue_date: Mapped[date]
    purpose: Mapped[str] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    student = relationship("Student")
    issued_by = relationship("User")
    lines = relationship("IssueLine", back_populates="issue", order_by="IssueLine.id")


class IssueLine(Base):
    __tablename__ = "issue_lines"
    id: Mapped[int] = mapped_column(primary_key=True)
    issue_id: Mapped[int] = mapped_column(ForeignKey("issues.id"), index=True)
    item_id: Mapped[int] = mapped_column(ForeignKey("items.id"), index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"))
    qty_issued: Mapped[int]
    qty_returned: Mapped[int] = mapped_column(default=0)
    due_date: Mapped[date] = mapped_column(index=True)
    renewal_count: Mapped[int] = mapped_column(default=0)
    status: Mapped[LineStatus] = mapped_column(E(LineStatus), default=LineStatus.OPEN)
    issue = relationship("Issue", back_populates="lines")
    item = relationship("Item")
    asset = relationship("Asset")
    __table_args__ = (
        CheckConstraint("qty_issued>0 AND qty_returned>=0 AND qty_returned<=qty_issued", name="ck_line_qty"),
        # Rule 4 enforced in the DB: an asset can have at most ONE open issue line at any time.
        Index("uq_open_asset", "asset_id", unique=True,
              sqlite_where=sa.text("status='OPEN' AND asset_id IS NOT NULL"),
              postgresql_where=sa.text("status='OPEN' AND asset_id IS NOT NULL")),
    )

    @property
    def outstanding(self) -> int:
        return self.qty_issued - self.qty_returned


class ReturnRecord(Base):
    __tablename__ = "return_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    line_id: Mapped[int] = mapped_column(ForeignKey("issue_lines.id"), index=True)
    quantity: Mapped[int]
    condition: Mapped[Condition] = mapped_column(E(Condition))
    returned_on: Mapped[date]
    received_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    remarks: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    line = relationship("IssueLine")
    received_by = relationship("User")
    __table_args__ = (CheckConstraint("quantity>0", name="ck_return_qty"),)


class Renewal(Base):
    __tablename__ = "renewals"
    id: Mapped[int] = mapped_column(primary_key=True)
    line_id: Mapped[int] = mapped_column(ForeignKey("issue_lines.id"), index=True)
    requested_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    requested_on: Mapped[date]
    reason: Mapped[str | None] = mapped_column(String(300))
    status: Mapped[RenewalStatus] = mapped_column(E(RenewalStatus), default=RenewalStatus.PENDING)
    decided_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    decided_on: Mapped[date | None]
    remarks: Mapped[str | None] = mapped_column(String(300))
    previous_due: Mapped[date | None]
    revised_due: Mapped[date | None]
    line = relationship("IssueLine")
    decided_by = relationship("User", foreign_keys=[decided_by_id])
    __table_args__ = (
        Index("uq_one_pending_renewal", "line_id", unique=True,
              sqlite_where=sa.text("status='PENDING'"), postgresql_where=sa.text("status='PENDING'")),
    )


class StockAdjustment(Base):
    __tablename__ = "stock_adjustments"
    id: Mapped[int] = mapped_column(primary_key=True)
    item_id: Mapped[int] = mapped_column(ForeignKey("items.id"), index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"))
    action: Mapped[str] = mapped_column(String(32))
    from_bucket: Mapped[str | None] = mapped_column(String(24))
    to_bucket: Mapped[str | None] = mapped_column(String(24))
    quantity: Mapped[int]
    reason: Mapped[str] = mapped_column(String(300))
    by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    adjusted_on: Mapped[date]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    item = relationship("Item")
    by = relationship("User")


class AuditLog(Base):
    """Append-only, HMAC hash-chained. Edits/deletes are blocked by DB triggers AND detectable by /admin/audit/verify."""
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[str] = mapped_column(String(32))
    actor_id: Mapped[int | None]
    actor_role: Mapped[str | None] = mapped_column(String(24))
    action: Mapped[str] = mapped_column(String(64), index=True)
    entity: Mapped[str | None] = mapped_column(String(48))
    entity_id: Mapped[str | None] = mapped_column(String(48))
    detail: Mapped[str | None] = mapped_column(sa.Text)
    ip: Mapped[str | None] = mapped_column(String(64))
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


_IMMUTABLE = ("audit_logs", "return_records", "stock_adjustments")


@event.listens_for(Base.metadata, "after_create")
def _immutability_triggers(target, connection, **kw):
    if connection.dialect.name != "sqlite":
        return
    for t in _IMMUTABLE:
        for op in ("UPDATE", "DELETE"):
            connection.exec_driver_sql(
                f"CREATE TRIGGER IF NOT EXISTS {t}_no_{op.lower()} BEFORE {op} ON {t} "
                f"BEGIN SELECT RAISE(ABORT, '{t} is append-only'); END")
