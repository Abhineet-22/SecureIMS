# Department Inventory & Student Item Issue – Secure Backend

FastAPI + SQLAlchemy 2 (ORM, parameterised queries only) · SQLite by default, Postgres-ready · 47 automated tests (`pytest`).

## Quick start
```bash
pip install -r requirements.txt
cp .env.example .env
python -m app.cli gen-key            # paste output into INV_MASTER_KEY in .env  (NEVER commit .env)
python -m app.cli create-admin       # password is typed hidden, never on the command line
uvicorn app.main:app --no-server-header      # docs at /docs (disabled when INV_ENV=production)
pytest -q
```
Flow: admin logs in → creates coordinator/staff (`POST /admin/users`) → coordinator creates locations, items, assets, students
(`POST /students` returns a one-time temporary password; the student must change it on first login).

## Request pipeline (every request, in order)
```
Client ─TLS(reverse proxy)─▶ TrustedHost allow-list ─▶ body-size cap (1 MB) / no chunked writes ─▶ CORS allow-list (no *)
  ─▶ global rate limit (240/min/IP) [+ login 10/min/IP]
  ─▶ Pydantic validation (strict types, regex allow-lists, length caps, unknown fields rejected, control chars rejected)
  ─▶ Authentication: JWT (HS256 pinned, iss/aud/exp/jti/ver required) → user re-loaded from DB (role never trusted from token)
  ─▶ Authorisation: role check (ADMIN > COORDINATOR > STAFF > STUDENT) + object-level check (students only via /me/*, identity from token)
  ─▶ Business rules inside ONE DB transaction (atomic conditional UPDATEs; DB CHECK/UNIQUE constraints as last line of defence)
  ─▶ Hash-chained audit entry written in the same transaction ─▶ commit
  ─▶ Response: security headers, no-store, generic errors (no stack traces, no echo of input)
```

## Secrets: what is hashed, what is encrypted
| Data | Protection |
|---|---|
| Passwords | HMAC-SHA256 with secret pepper → **Argon2id** (RFC 9106). Not reversible. Temp passwords are random and must be changed at first login. |
| Student name, enrolment no., email, phone | **AES-256-GCM** per field, random nonce, AAD = `table.column` (ciphertext can't be swapped between columns). |
| Enrolment-number lookup/uniqueness | **HMAC-SHA256 blind index** (searchable without decrypting; not reversible). |
| Refresh tokens | Random 384-bit; only the **SHA-256** is stored; rotated on every use; replay of an old one revokes *all* sessions. |
| Access tokens | 15-minute JWT; `token_version` in DB kills every token instantly (password change, disable, logout-all). |
| Audit log | HMAC-chained (each row covers the previous hash) + SQLite triggers forbid UPDATE/DELETE on `audit_logs`, `return_records`, `stock_adjustments`. `GET /admin/audit/verify` detects tampering. |
| Keys | One 32-byte `INV_MASTER_KEY` from the environment → HKDF → separate keys for encryption, blind index, pepper, audit, JWT. Nothing secret in code or DB. |

## Attack → defence
| Attack | Defence (test) |
|---|---|
| SQL injection | ORM/bound parameters only, no string-built SQL; regex allow-lists; typed + bounded ids (`test_sqli_*`) |
| Broken access control / IDOR | role dependency on every route; `/me/*` derives the student from the token; "not yours" == "doesn't exist" (404) |
| Mass assignment | `extra="forbid"` on every input model |
| Brute force / user enumeration | Argon2 cost, per-IP rate limit, lockout (5 fails → 15 min), identical error + equal timing for unknown user / wrong password / locked |
| JWT forgery (`alg:none`, tampered role, expired) | algorithm pinned, signature + claims verified, role read from DB |
| Token theft | short expiry, refresh rotation + reuse detection, instant revocation |
| Race conditions (double-issue, oversell) | atomic `UPDATE … WHERE available >= n`; partial UNIQUE index = one open issue per asset; writers serialised |
| Data tampering | DB CHECK keeps `total = available+issued+damaged+lost+maintenance` and ≥ 0 even if the app is bypassed |
| CSV/Excel formula injection | exported cells starting `= + - @` are neutralised |
| XSS / clickjacking / sniffing | JSON-only API, `CSP default-src 'none'`, `nosniff`, `X-Frame-Options: DENY`, HSTS. **The frontend must render with `textContent`, never `innerHTML`.** |
| Info leak | generic 500s, validation errors never echo values, docs off in production |
| Insider abuse / repudiation | every issue/return/renewal/stock change/login/denied access logged with user, role, IP, time |

## Roles
`ADMIN` users + audit · `COORDINATOR` inventory, students, stock, renewal decisions, policy · `STAFF` issue/return/view/reports · `STUDENT` own records only.

## Problem-statement rules → where enforced (`app/services.py`)
Registered students only · usable condition and availability · one holder per asset (DB index) · due = issue + 15 days ·
renewal request never moves the due date; approval = existing due + 15; rejection needs remarks · returns update stock only when condition is recorded ·
partial returns · every action audited · a failed issue rolls back everything, with messages like
*"Five Adapters were requested, but only three are currently available."*

## API map
`/auth/{login,refresh,logout,change-password,me}` · `/admin/{users,audit,audit/verify}` · `/students` · `/locations` ·
`/items`, `/items/{id}/{assets,adjust}`, `/assets/{id}/status` · `/policy` ·
`POST /issues`, `GET /issues/{id}/acknowledgement`, `POST /issue-lines/{id}/return`, `/issue-lines` ·
`/renewals`, `/renewals/{id}/decision` · `/overdue`, `/upcoming` · `/me/{issues,history,renewals,reminders}` ·
`/reports/{stock,transactions}?format=csv` (filters: student, item, programme, location, dates).

## Known limits / before real production
- The SQLite file isn't encrypted as a whole → use disk encryption or SQLCipher; field-level encryption already protects PII. For Postgres set `INV_DATABASE_URL` (the advisory-lock path for the audit chain is written but untested).
- Terminate TLS at a reverse proxy (nginx/Caddy). Behind one, per-IP limits see the proxy's IP unless you add trusted-proxy handling. The rate limiter is in-process (use Redis for several workers).
- No MFA or email reset flow (admin resets passwords). No key-rotation tool yet (ciphertext is version-prefixed `v1.` to allow it).
- Tables are created at startup; use Alembic migrations for real deployments. Run `pip-audit` on the dependencies.
