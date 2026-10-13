"""Attack-style tests: injection, authz bypass, token abuse, secrets at rest, tamper evidence, abuse limits."""
import base64
import json
import sqlite3
import time

import jwt
import pytest

from app import ratelimit
from app.config import get_settings
from app.db import SessionLocal, engine
from app.models import Role

from .conftest import STRONG, make_staff, make_student, new_qty_item


# ------------------------------------------------------------- SQL injection
SQLI = ["' OR '1'='1", "'; DROP TABLE users; --", "\" OR 1=1 --", "admin' --", "1; DELETE FROM items", "' UNION SELECT password_hash FROM users --"]


@pytest.mark.parametrize("payload", SQLI)
def test_sqli_login(client, payload):
    r = client.post("/auth/login", json={"username": payload, "password": payload})
    assert r.status_code == 401 and r.json() == {"detail": "Invalid credentials"}


@pytest.mark.parametrize("payload", SQLI)
def test_sqli_in_filters_and_bodies(client, coord, payload):
    h = coord["h"]
    assert client.get("/students", headers=h, params={"programme": payload}).json() == []
    assert client.get("/items", headers=h, params={"category": payload}).json() == []
    assert client.get("/students", headers=h, params={"enrolment_no": payload}).status_code == 422   # allow-list regex
    assert client.get("/admin/audit", headers=h, params={"action": payload}).status_code == 403
    # stored verbatim as inert data, never executed
    r = client.post("/locations", headers=h, json={"name": payload[:100] + str(time.time_ns()), "kind": "OTHER"})
    assert r.status_code == 201
    assert client.post("/items", headers=h, json={"code": payload, "name": "x", "category": "c", "kind": "QUANTITY"}).status_code == 422
    # the DB is intact
    assert client.get("/items", headers=h).status_code == 200 and client.get("/locations", headers=h).status_code == 200


def test_sqli_path_and_types(client, coord):
    assert client.get("/items/1;DROP TABLE items", headers=coord["h"]).status_code == 422
    assert client.get("/items/abc", headers=coord["h"]).status_code == 422
    assert client.get("/items/99999999999999999999", headers=coord["h"]).status_code in (404, 422)


# ------------------------------------------------------------- input validation
def test_unknown_fields_and_control_chars_rejected(client, coord):
    base = {"enrolment_no": "ZZ12345", "name": "A", "programme": "P", "semester": 1, "email": "a@b.co"}
    assert client.post("/students", headers=coord["h"], json={**base, "is_admin": True}).status_code == 422         # mass assignment
    assert client.post("/students", headers=coord["h"], json={**base, "name": "bad\x00name"}).status_code == 422
    assert client.post("/students", headers=coord["h"], json={**base, "semester": "1; DROP"}).status_code == 422
    assert client.post("/students", headers=coord["h"], json={**base, "name": "x" * 500}).status_code == 422


def test_validation_errors_do_not_echo_input(client, coord):
    secret = "SuperSecretValue123"
    r = client.post("/students", headers=coord["h"], json={"enrolment_no": secret + "!!", "name": "A", "programme": "P", "semester": 1, "email": "a@b.co"})
    assert r.status_code == 422 and secret not in r.text


def test_oversized_body_rejected(client, coord):
    r = client.post("/locations", headers={**coord["h"], "Content-Type": "application/json"}, content=b'{"name":"' + b"a" * 1_100_000 + b'"}')
    assert r.status_code == 413


def test_audit_records_actor_and_ip(client, admin, coord):
    new_qty_item(client, coord)
    rows = client.get("/admin/audit", headers=admin["h"], params={"action": "ITEM_CREATE"}).json()
    assert rows and rows[0]["role"] == "COORDINATOR" and rows[0]["ip"]


# ------------------------------------------------------------- authentication
def test_requires_auth(client):
    for method, path in (("GET", "/items"), ("GET", "/students"), ("GET", "/me/issues"), ("GET", "/reports/stock"), ("GET", "/admin/users"), ("POST", "/issues")):
        assert client.request(method, path).status_code == 401


def _forge(claims, key, alg="HS256"):
    return jwt.encode(claims, key, algorithm=alg)


def test_forged_and_malformed_tokens(client, student):
    now = int(time.time())
    claims = {"sub": "1", "role": "ADMIN", "ver": 0, "jti": "x", "iat": now, "exp": now + 600, "iss": "dept-inventory", "aud": "dept-inventory-api"}
    none_tok = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode() + "." + base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode() + "."
    for tok in (none_tok, _forge(claims, "guessed-secret-guessed-secret-1234"), "garbage", "a.b.c", ""):
        assert client.get("/items", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
    # a real student token with a tampered role claim (signature breaks)
    good = student["h"]["Authorization"].split()[1]
    h, p, s = good.split(".")
    pl = json.loads(base64.urlsafe_b64decode(p + "=="))
    pl["role"] = "ADMIN"
    forged = h + "." + base64.urlsafe_b64encode(json.dumps(pl).encode()).rstrip(b"=").decode() + "." + s
    assert client.get("/admin/users", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_expired_token(client, student):
    from app.security import _keys
    now = int(time.time())
    t = _forge({"sub": str(1), "ver": 0, "jti": "x", "iat": now - 1000, "exp": now - 10, "iss": "dept-inventory", "aud": "dept-inventory-api"}, _keys()["jwt"])
    assert client.get("/me/issues", headers={"Authorization": f"Bearer {t}"}).status_code == 401


def test_lockout_after_repeated_failures(client, coord):
    s = make_staff(client, Role.STAFF)
    for _ in range(get_settings().login_max_failures):
        assert client.post("/auth/login", json={"username": s["username"], "password": "wrong-password-1"}).status_code == 401
    # even the CORRECT password is refused while locked, with the same generic message
    r = client.post("/auth/login", json={"username": s["username"], "password": STRONG})
    assert r.status_code == 401 and r.json()["detail"] == "Invalid credentials"


def test_temp_password_must_be_changed(client, coord):
    r = client.post("/students", headers=coord["h"], json={"enrolment_no": "TMP12345", "name": "T", "programme": "P", "semester": 1, "email": "t@t.co"})
    d = r.json()
    tok = client.post("/auth/login", json={"username": d["username"], "password": d["temporary_password"]}).json()
    assert tok["must_change_password"] is True
    h = {"Authorization": f"Bearer {tok['access_token']}"}
    assert client.get("/me/issues", headers=h).status_code == 403
    assert client.post("/auth/change-password", headers=h, json={"old_password": d["temporary_password"], "new_password": "short"}).status_code == 422
    assert client.post("/auth/change-password", headers=h, json={"old_password": d["temporary_password"], "new_password": STRONG}).status_code == 204
    assert client.get("/auth/me", headers=h).status_code == 401           # old access token died with the password change
    assert client.post("/auth/refresh", json={"refresh_token": tok["refresh_token"]}).status_code == 401


def test_refresh_rotation_and_reuse_detection(client):
    s = make_staff(client, Role.STAFF)
    t1 = s["tok"]
    t2 = client.post("/auth/refresh", json={"refresh_token": t1["refresh_token"]}).json()
    assert t2["refresh_token"] != t1["refresh_token"]
    # replaying the already-used token => treated as theft: everything is revoked
    assert client.post("/auth/refresh", json={"refresh_token": t1["refresh_token"]}).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": t2["refresh_token"]}).status_code == 401
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {t2['access_token']}"}).status_code == 401


def test_logout_revokes_refresh(client):
    s = make_staff(client, Role.STAFF)
    assert client.post("/auth/logout", headers=s["h"], json={"refresh_token": s["tok"]["refresh_token"]}).status_code == 204
    assert client.post("/auth/refresh", json={"refresh_token": s["tok"]["refresh_token"]}).status_code == 401


def test_login_rate_limit(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "rate_limit_enabled", True)
    ratelimit.reset()
    codes = [client.post("/auth/login", json={"username": "nobody", "password": "x"}).status_code for _ in range(14)]
    assert codes[:10] == [401] * 10 and 429 in codes[10:]


# ------------------------------------------------------------- authorisation (RBAC + object level)
def test_student_cannot_touch_staff_endpoints(client, student):
    h = student["h"]
    for method, path, body in (("GET", "/items", None), ("GET", "/students", None), ("GET", "/reports/stock", None), ("GET", "/overdue", None),
                               ("POST", "/items", {"code": "X1", "name": "n", "category": "c", "kind": "QUANTITY"}), ("GET", "/admin/users", None),
                               ("GET", "/admin/audit", None), ("PUT", "/policy", {"max_renewals_per_line": 99}), ("POST", "/issues", {"student_id": student["id"], "purpose": "abc", "lines": [{"item_id": 1}]})):
        assert client.request(method, path, headers=h, json=body).status_code == 403, path


def test_staff_role_limits(client, staff):
    h = staff["h"]
    assert client.post("/items", headers=h, json={"code": "S1", "name": "n", "category": "c", "kind": "QUANTITY"}).status_code == 403
    assert client.post("/students", headers=h, json={"enrolment_no": "STF12345", "name": "n", "programme": "p", "semester": 1, "email": "a@b.co"}).status_code == 403
    assert client.get("/admin/audit", headers=h).status_code == 403
    assert client.get("/items", headers=h).status_code == 200


def test_coordinator_is_not_admin(client, coord):
    assert client.get("/admin/users", headers=coord["h"]).status_code == 403
    assert client.post("/admin/users", headers=coord["h"], json={"username": "evil", "role": "ADMIN"}).status_code == 403


def test_no_idor_between_students(client, coord, staff):
    a, b = make_student(client, coord), make_student(client, coord)
    item = new_qty_item(client, coord)
    line = client.post("/issues", headers=staff["h"], json={"student_id": a["id"], "purpose": "project", "lines": [{"item_id": item["id"]}]}).json()["lines"][0]
    # B cannot see A's lines, nor renew them, and the error is identical to "does not exist"
    assert client.get("/me/issues", headers=b["h"]).json() == []
    r = client.post("/me/renewals", headers=b["h"], json={"line_id": line["line_id"]})
    r2 = client.post("/me/renewals", headers=b["h"], json={"line_id": 987654})
    assert r.status_code == r2.status_code == 404 and r.json() == r2.json()
    # student id in the URL/body is ignored: /me/* uses the token
    assert client.get("/me/issues", headers=b["h"], params={"student_id": a["id"]}).json() == []
    assert len(client.get("/me/issues", headers=a["h"]).json()) == 1


# ------------------------------------------------------------- secrets at rest
def test_pii_and_credentials_encrypted_at_rest(client, coord):
    r = client.post("/students", headers=coord["h"], json={"enrolment_no": "RAW99999", "name": "Zaphod Beeblebrox", "programme": "P", "semester": 1,
                                                           "email": "zaphod@galaxy.example", "phone": "+919876543210"}).json()
    raw = sqlite3.connect(engine.url.database)
    dump = " ".join(str(c) for t in ("students", "users") for row in raw.execute(f"SELECT * FROM {t}") for c in row)
    for secret in ("Zaphod", "zaphod@galaxy", "9876543210", "RAW99999", r["temporary_password"]):
        assert secret not in dump, f"{secret!r} stored in plaintext"
    ph = raw.execute("SELECT password_hash FROM users WHERE username='raw99999'").fetchone()[0]
    assert ph.startswith("$argon2id$")
    # still readable through the API (decrypted with the key)
    got = client.get(f"/students/{r['student']['id']}", headers=coord["h"]).json()
    assert got["name"] == "Zaphod Beeblebrox" and got["email"] == "zaphod@galaxy.example"
    # exact lookup via blind index works
    assert client.get("/students", headers=coord["h"], params={"enrolment_no": "raw99999"}).json()[0]["id"] == r["student"]["id"]
    # same plaintext encrypts differently every time (random nonce)
    from app.security import encrypt_field
    assert encrypt_field("same", "a.b") != encrypt_field("same", "a.b")


def test_ciphertext_bound_to_its_column(client):
    from app.security import decrypt_field, encrypt_field
    ct = encrypt_field("secret", "students.name")
    assert decrypt_field(ct, "students.name") == "secret"
    with pytest.raises(Exception):
        decrypt_field(ct, "students.email")      # swapping ciphertext between columns fails authentication


def test_responses_never_leak_secrets(client, coord, admin):
    users = client.get("/admin/users", headers=admin["h"]).text
    assert "argon2" not in users and "password_hash" not in users
    assert "enrolment_idx" not in client.get("/students", headers=coord["h"]).text


# ------------------------------------------------------------- tamper evidence
def test_audit_chain_detects_tampering(client, admin, coord):
    new_qty_item(client, coord)
    assert client.get("/admin/audit/verify", headers=admin["h"]).json()["valid"] is True
    raw = sqlite3.connect(engine.url.database, isolation_level=None)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):         # DB trigger blocks edits
        raw.execute("UPDATE audit_logs SET action='NOTHING' WHERE id=1")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        raw.execute("DELETE FROM audit_logs")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        raw.execute("UPDATE return_records SET quantity=99")
    # an attacker with full file access who drops the trigger is still caught by the HMAC chain
    raw.execute("DROP TRIGGER audit_logs_no_update")
    raw.execute("UPDATE audit_logs SET action='FORGED' WHERE id=(SELECT max(id)-2 FROM audit_logs)")
    res = client.get("/admin/audit/verify", headers=admin["h"]).json()
    assert res["valid"] is False and "broken_at_id" in res
    # restore for other tests: rebuild trigger & repair is not possible (that's the point) -> mark by re-creating trigger only
    raw.execute("CREATE TRIGGER audit_logs_no_update BEFORE UPDATE ON audit_logs BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END")


def test_db_rejects_unbalanced_stock_even_if_app_is_bypassed(client, coord):
    item = new_qty_item(client, coord, qty=5)
    raw = sqlite3.connect(engine.url.database)
    with pytest.raises(sqlite3.IntegrityError):
        raw.execute("UPDATE items SET qty_available=qty_available+100 WHERE id=?", (item["id"],))
    with pytest.raises(sqlite3.IntegrityError):
        raw.execute("UPDATE items SET qty_available=-1, qty_total=4 WHERE id=?", (item["id"],))


# ------------------------------------------------------------- hardening
def test_security_headers_and_no_stack_traces(client):
    r = client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in r.headers["content-security-policy"] and "strict-transport-security" in r.headers
    assert r.headers["cache-control"] == "no-store" and "x-request-id" in r.headers
    r = client.get("/definitely-not-here")
    assert r.status_code == 404 and "Traceback" not in r.text


def test_host_header_allowlist(client):
    assert client.get("/health", headers={"Host": "evil.example"}).status_code == 400


def test_cors_not_open(client):
    r = client.options("/items", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in r.headers
