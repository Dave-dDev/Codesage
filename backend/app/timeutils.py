from __future__ import annotations

from datetime import datetime, timezone


def ensure_utc(value: datetime) -> datetime:
    """Return an aware UTC datetime, treating naive database values as UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def iso_utc(value: datetime) -> str:
    return ensure_utc(value).isoformat()
