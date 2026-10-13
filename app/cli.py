"""python -m app.cli gen-key | create-admin | seed-demo"""
import base64
import getpass
import os
import sys


def gen_key() -> None:
    print(base64.urlsafe_b64encode(os.urandom(32)).decode())


def create_admin() -> None:
    from .audit import audit
    from .db import Base, SessionLocal, engine
    from .models import Policy, Role, User
    from .security import hash_password, password_problems
    Base.metadata.create_all(engine)
    username = input("Admin username: ").strip().lower()
    pw = getpass.getpass("Password (hidden): ")  # never passed as an argument => not in shell history / ps
    if getpass.getpass("Repeat: ") != pw:
        sys.exit("Passwords differ")
    if problems := password_problems(pw, username):
        sys.exit("Password " + "; ".join(problems))
    with SessionLocal() as db:
        if db.get(Policy, 1) is None:
            db.add(Policy(id=1))
        u = User(username=username, password_hash=hash_password(pw), role=Role.ADMIN, must_change_password=False)
        db.add(u)
        db.flush()
        audit(db, None, "ADMIN_BOOTSTRAP", "user", u.id)
        db.commit()
    print("Admin created.")


def seed_demo() -> None:
    """Pre-populates demo coordinator, staff, student, location, and items for rapid testing."""
    from sqlalchemy import select
    from .audit import audit
    from .db import Base, SessionLocal, engine
    from .models import Policy, Role, User, Student, Location, LocationKind, Item, ItemKind, Asset, Condition, AssetStatus, StockAdjustment
    from .security import hash_password, blind_index
    from .clock import today

    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        if db.get(Policy, 1) is None:
            db.add(Policy(id=1))

        # 1. Coordinator
        coord = db.scalar(select(User).where(User.username == "coord1"))
        if not coord:
            coord = User(username="coord1", password_hash=hash_password("CoordPass1234!"), role=Role.COORDINATOR, must_change_password=False)
            db.add(coord)
            db.flush()
            audit(db, None, "SEED_BOOTSTRAP", "user", coord.id)
            print("Coordinator created -> Username: coord1 | Password: CoordPass1234!")
        else:
            print("Coordinator coord1 already exists.")

        # 2. Staff
        staff = db.scalar(select(User).where(User.username == "staff1"))
        if not staff:
            staff = User(username="staff1", password_hash=hash_password("StaffPass1234!"), role=Role.STAFF, must_change_password=False)
            db.add(staff)
            db.flush()
            audit(db, None, "SEED_BOOTSTRAP", "user", staff.id)
            print("Staff created       -> Username: staff1 | Password: StaffPass1234!")
        else:
            print("Staff staff1 already exists.")

        # 3. Student
        enrol = "ENR2026001"
        idx = blind_index(enrol)
        stud = db.scalar(select(Student).where(Student.enrolment_idx == idx))
        if not stud:
            stud = Student(
                enrolment_no=enrol,
                enrolment_idx=idx,
                name="Alex Turner",
                programme="M.Sc. DFIS",
                semester=1,
                email="alex.turner@dept.edu",
                phone="+919876543210"
            )
            db.add(stud)
            db.flush()
            s_user = User(username=enrol.lower(), password_hash=hash_password("StudentPass1234!"), role=Role.STUDENT, student_id=stud.id, must_change_password=False)
            db.add(s_user)
            db.flush()
            audit(db, None, "SEED_BOOTSTRAP", "student", stud.id)
            print(f"Student created     -> Username: {enrol.lower()} | Password: StudentPass1234! | Enrolment: {enrol}")
        else:
            print(f"Student {enrol} already exists.")

        # 4. Location
        loc = db.scalar(select(Location).where(Location.name == "Cyber Forensics Lab"))
        if not loc:
            loc = Location(name="Cyber Forensics Lab", kind=LocationKind.LABORATORY, description="Room 402 Digital Forensics & Hardware Lab")
            db.add(loc)
            db.flush()

        # 5. Items (Quantity & Asset)
        cable = db.scalar(select(Item).where(Item.code == "USB-C-101"))
        if not cable:
            cable = Item(code="USB-C-101", name="High-Speed USB-C Cable", category="Cables", kind=ItemKind.QUANTITY, location_id=loc.id, max_issue_qty=3, qty_total=25, qty_available=25)
            db.add(cable)
            db.flush()
            db.add(StockAdjustment(item_id=cable.id, action="ADD", to_bucket="AVAILABLE", quantity=25, reason="Initial demo stock", by_id=coord.id, adjusted_on=today()))

        board = db.scalar(select(Item).where(Item.code == "FPGA-DEV-01"))
        if not board:
            board = Item(code="FPGA-DEV-01", name="FPGA Hardware Board", category="Hardware Boards", kind=ItemKind.ASSET, location_id=loc.id)
            db.add(board)
            db.flush()
            for i in range(1, 4):
                tag = f"FPGA-TAG-{i:03d}"
                asset = Asset(asset_tag=tag, item_id=board.id, serial_no=f"SN-FPGA-{i}00", location_id=loc.id, condition=Condition.GOOD, status=AssetStatus.AVAILABLE)
                db.add(asset)
                db.flush()
                db.add(StockAdjustment(item_id=board.id, asset_id=asset.id, action="ADD", to_bucket="AVAILABLE", quantity=1, reason="New demo asset", by_id=coord.id, adjusted_on=today()))

        db.commit()
    print("\nSetup complete! You can now log into any of these accounts in the frontend at http://localhost:5174/")


if __name__ == "__main__":
    commands = {
        "gen-key": gen_key,
        "create-admin": create_admin,
        "seed-demo": seed_demo,
    }
    commands.get(sys.argv[1] if len(sys.argv) > 1 else "", lambda: sys.exit(__doc__))()
