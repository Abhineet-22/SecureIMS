"""All cryptography lives here.

* Passwords  -> HMAC-SHA256 pepper, then Argon2id (RFC 9106 profile). Never reversible.
* PII fields -> AES-256-GCM, per-value random nonce, AAD binds ciphertext to its column.
* Lookups on encrypted fields -> HMAC-SHA256 "blind index" (searchable, not reversible).
* Tokens     -> short-lived HS256 JWT access token; opaque random refresh token stored only as SHA-256.
* All keys are derived from ONE master secret via HKDF with distinct labels (key separation).
"""
import base64
import hashlib
import hmac
import os
import secrets
import uuid
from datetime import timedelta
from functools import lru_cache

import jwt
from argon2 import PasswordHasher, profiles
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .clock import utcnow
from .config import get_settings

ISSUER = "dept-inventory"
AUDIENCE = "dept-inventory-api"


# ---------------------------------------------------------------- keys
@lru_cache
def _keys() -> dict[str, bytes]:
    v = get_settings().master_key.get_secret_value()
    master = base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))

    def derive(label: str) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=f"inv-v1:{label}".encode()).derive(master)

    return {k: derive(k) for k in ("enc", "blind", "pepper", "audit", "jwt")}


def audit_key() -> bytes:
    return _keys()["audit"]


# ---------------------------------------------------------------- passwords
_ph = PasswordHasher.from_parameters(profiles.RFC_9106_LOW_MEMORY)
_COMMON = {"password1234", "123456789012", "qwerty123456", "admin1234567", "iloveyou1234", "welcome12345"}


def _prehash(password: str) -> str:
    return base64.b64encode(hmac.new(_keys()["pepper"], password.encode(), hashlib.sha256).digest()).decode()


def hash_password(password: str) -> str:
    return _ph.hash(_prehash(password))


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _ph.verify(stored_hash, _prehash(password))
    except (VerifyMismatchError, InvalidHashError, VerificationError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return _ph.check_needs_rehash(stored_hash)


@lru_cache
def dummy_hash() -> str:
    """Verified against when a username doesn't exist -> equal timing, no user enumeration."""
    return hash_password(secrets.token_urlsafe(16))


def password_problems(password: str, username: str = "") -> list[str]:
    errs = []
    if not 12 <= len(password) <= 128:
        errs.append("must be 12-128 characters long")
    if not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        errs.append("must contain letters and digits")
    if password.lower() in _COMMON or (username and username.lower() in password.lower()):
        errs.append("is too easy to guess")
    return errs


def generate_temp_password() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(16))
        if any(c.isupper() for c in pw) and any(c.islower() for c in pw) and any(c.isdigit() for c in pw):
            return pw


# ---------------------------------------------------------------- field encryption
def encrypt_field(plaintext: str, aad: str) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(_keys()["enc"]).encrypt(nonce, plaintext.encode(), aad.encode())
    return "v1." + base64.urlsafe_b64encode(nonce + ct).decode()


def decrypt_field(token: str, aad: str) -> str:
    version, _, body = token.partition(".")
    if version != "v1":
        raise ValueError("unknown ciphertext version")
    raw = base64.urlsafe_b64decode(body)
    return AESGCM(_keys()["enc"]).decrypt(raw[:12], raw[12:], aad.encode()).decode()


def blind_index(value: str) -> str:
    return hmac.new(_keys()["blind"], value.strip().upper().encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------- tokens
def create_access_token(user_id: int, role: str, token_version: int) -> tuple[str, int]:
    minutes = get_settings().access_token_minutes
    now = utcnow()
    claims = {
        "iss": ISSUER, "aud": AUDIENCE, "sub": str(user_id), "role": role, "ver": token_version,
        "jti": uuid.uuid4().hex, "iat": now, "exp": now + timedelta(minutes=minutes),
    }
    return jwt.encode(claims, _keys()["jwt"], algorithm="HS256"), minutes * 60


def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(
            token, _keys()["jwt"], algorithms=["HS256"], issuer=ISSUER, audience=AUDIENCE,
            options={"require": ["exp", "iat", "sub", "jti", "ver", "iss", "aud"]},
        )
    except jwt.PyJWTError:
        return None


def new_refresh_token() -> tuple[str, str]:
    raw = secrets.token_urlsafe(48)
    return raw, hash_refresh_token(raw)


def hash_refresh_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()
