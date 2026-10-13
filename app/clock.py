"""Single source of 'now'/'today' (department's timezone). Overridable in tests."""
from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo

from .config import get_settings

_today_override: date | None = None


def set_today(d: date | None) -> None:
    global _today_override
    _today_override = d


def today() -> date:
    return _today_override or datetime.now(ZoneInfo(get_settings().timezone)).date()


def utcnow() -> datetime:
    """Naive UTC datetime (stored uniformly in UTC)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
