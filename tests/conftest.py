import base64
import itertools
import os
import tempfile

_tmp = tempfile.mkdtemp()
os.environ["INV_MASTER_KEY"] = base64.urlsafe_b64encode(os.urandom(32)).decode()
os.environ["INV_DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["INV_RATE_LIMIT_ENABLED"] = "false"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import clock, ratelimit  # noqa: E402
from app.audit import audit  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Role, User  # noqa: E402
from app.security import hash_password  # noqa: E402

STRONG = "Str0ng-Passw0rd!x"
_n = itertools.count(1)


@pytest.fixture(scope="session")
def client():
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture(autouse=True)
def _reset():
    ratelimit.reset()
    clock.set_today(None)
    yield
    clock.set_today(None)


def _login(client, username, password):
    r = client.post("/auth/login", json={"username": username, "password": password})
    return r


def make_staff(client, role: Role) -> dict:
    """Create a ready-to-use user of `role` (bypasses the admin API only for the bootstrap admin)."""
    name = f"{role.value.lower()}{next(_n)}"
    with SessionLocal() as db:
        u = User(username=name, password_hash=hash_password(STRONG), role=role, must_change_password=False)
        db.add(u)
        db.flush()
        audit(db, None, "TEST_BOOTSTRAP", "user", u.id)
        db.commit()
    tok = _login(client, name, STRONG).json()
    return {"username": name, "h": {"Authorization": f"Bearer {tok['access_token']}"}, "tok": tok}


@pytest.fixture(scope="session")
def admin(client):
    return make_staff(client, Role.ADMIN)


@pytest.fixture(scope="session")
def coord(client):
    return make_staff(client, Role.COORDINATOR)


@pytest.fixture(scope="session")
def staff(client):
    return make_staff(client, Role.STAFF)


def make_student(client, coord, programme="M.Sc. DFIS", semester=1) -> dict:
    n = next(_n)
    enrol = f"ENR{1000 + n}"
    r = client.post("/students", headers=coord["h"], json={"enrolment_no": enrol, "name": f"Student {n}", "programme": programme,
                                                           "semester": semester, "email": f"s{n}@example.edu", "phone": "+919800000000"})
    assert r.status_code == 201, r.text
    d = r.json()
    tok = _login(client, d["username"], d["temporary_password"]).json()
    hh = {"Authorization": f"Bearer {tok['access_token']}"}
    assert client.post("/auth/change-password", headers=hh, json={"old_password": d["temporary_password"], "new_password": STRONG}).status_code == 204
    tok = _login(client, d["username"], STRONG).json()
    return {"id": d["student"]["id"], "enrol": enrol, "username": d["username"], "h": {"Authorization": f"Bearer {tok['access_token']}"}}


@pytest.fixture
def student(client, coord):
    return make_student(client, coord)


_codes = itertools.count(1)


def new_qty_item(client, coord, qty=20, name="USB Cable", **kw):
    code = f"Q{next(_codes)}"
    r = client.post("/items", headers=coord["h"], json={"code": code, "name": name, "category": "Cables", "kind": "QUANTITY", "initial_quantity": qty, **kw})
    assert r.status_code == 201, r.text
    return r.json()


def new_asset_item(client, coord, n=3, name="Development Board"):
    code = f"A{next(_codes)}"
    r = client.post("/items", headers=coord["h"], json={"code": code, "name": name, "category": "Boards", "kind": "ASSET"})
    assert r.status_code == 201, r.text
    item = r.json()
    assets = []
    for i in range(n):
        ar = client.post(f"/items/{item['id']}/assets", headers=coord["h"], json={"asset_tag": f"{code}-{i:03d}", "serial_no": f"SN{i}"})
        assert ar.status_code == 201, ar.text
        assets.append(ar.json())
    return item, assets


def stock(client, coord, item_id):
    rows = client.get("/reports/stock", headers=coord["h"]).json()
    return next(r for r in rows if r["item_id"] == item_id)
