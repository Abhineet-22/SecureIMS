"""Central configuration. Secrets come ONLY from the environment (never from code)."""
import base64
from functools import lru_cache

from pathlib import Path
from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="INV_",
        env_file=(_BASE_DIR / ".env", _BASE_DIR / "env", ".env", "env"),
        extra="ignore",
    )

    env: str = "development"
    master_key: SecretStr  # base64url, 32 bytes. All other keys are derived from it (HKDF).
    database_url: str = "sqlite:///./inventory.db"

    access_token_minutes: int = 15
    refresh_token_days: int = 7
    login_max_failures: int = 5
    lockout_minutes: int = 15

    cors_origins: list[str] = []
    allowed_hosts: list[str] = ["localhost", "127.0.0.1"]
    timezone: str = "Asia/Kolkata"
    max_body_bytes: int = 1_000_000

    rate_limit_enabled: bool = True
    login_rate_per_min: int = 10
    global_rate_per_min: int = 240

    @field_validator("master_key")
    @classmethod
    def _check_key(cls, v: SecretStr) -> SecretStr:
        try:
            raw = base64.urlsafe_b64decode(v.get_secret_value() + "=" * (-len(v.get_secret_value()) % 4))
        except Exception as exc:  # noqa: BLE001
            raise ValueError("INV_MASTER_KEY must be base64url") from exc
        if len(raw) != 32:
            raise ValueError("INV_MASTER_KEY must decode to exactly 32 bytes (run: python -m app.cli gen-key)")
        return v

    @model_validator(mode="after")
    def _prod_checks(self) -> "Settings":
        if self.env == "production":
            if "*" in self.cors_origins or "*" in self.allowed_hosts:
                raise ValueError("Wildcard CORS/hosts are not allowed in production")
            if not self.rate_limit_enabled:
                raise ValueError("Rate limiting cannot be disabled in production")
        return self

    @property
    def is_prod(self) -> bool:
        return self.env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
