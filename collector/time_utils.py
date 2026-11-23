"""UTC timestamp parsing, formatting, month bounds, and epoch unit verification."""

from __future__ import annotations

import calendar
from datetime import datetime, timedelta, timezone
from typing import Any, List, Tuple

from .constants import (
    EXIT_POLICY_REJECTED,
    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
    MONTH_LABEL_RE,
    CollectorError,
)

EPOCH_UTC = datetime(1970, 1, 1, tzinfo=timezone.utc)


def parse_iso_utc_to_ms(value: str) -> int:
    """Parse an explicit UTC ISO-8601 string into integer epoch milliseconds."""
    if not isinstance(value, str) or not value.strip():
        raise CollectorError(
            "BLOCKED_INVALID_TIMESTAMP",
            f"Expected non-empty ISO-8601 UTC string, got {value!r}",
            EXIT_POLICY_REJECTED,
        )
    raw = value.strip()
    if raw.endswith("Z"):
        normalized = raw[:-1] + "+00:00"
    elif raw.endswith("+00:00") or raw.endswith("-00:00"):
        normalized = raw
    else:
        raise CollectorError(
            "BLOCKED_INVALID_TIMESTAMP",
            f"Timestamp must explicitly specify UTC ('Z' or '+00:00'): {value!r}",
            EXIT_POLICY_REJECTED,
        )
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise CollectorError(
            "BLOCKED_INVALID_TIMESTAMP",
            f"Malformed ISO-8601 UTC timestamp {value!r}: {exc}",
            EXIT_POLICY_REJECTED,
        ) from exc
    if dt.tzinfo is None:
        raise CollectorError(
            "BLOCKED_INVALID_TIMESTAMP",
            f"Naive timestamp rejected: {value!r}",
            EXIT_POLICY_REJECTED,
        )
    dt_utc = dt.astimezone(timezone.utc)
    if dt_utc.microsecond % 1000 != 0:
        raise CollectorError(
            "BLOCKED_INVALID_TIMESTAMP",
            f"Sub-millisecond precision not supported in ms bounds: {value!r}",
            EXIT_POLICY_REJECTED,
        )
    delta = dt_utc - EPOCH_UTC
    return (delta.days * 86_400 + delta.seconds) * 1000 + (dt_utc.microsecond // 1000)


def format_utc_ms(epoch_ms: int) -> str:
    """Format epoch milliseconds into ISO-8601 UTC preserving subsecond ms if non-zero."""
    dt = EPOCH_UTC + timedelta(milliseconds=epoch_ms)
    if dt.microsecond:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_month_label(ym: str) -> Tuple[int, int]:
    """Validate YYYY-MM string and return (year, month)."""
    if not isinstance(ym, str):
        raise CollectorError(
            "BLOCKED_INVALID_MONTH",
            f"Month label must be a string YYYY-MM, got {ym!r}",
            EXIT_POLICY_REJECTED,
        )
    m = MONTH_LABEL_RE.match(ym.strip())
    if not m:
        raise CollectorError(
            "BLOCKED_INVALID_MONTH",
            f"Invalid month label (expected YYYY-MM): {ym!r}",
            EXIT_POLICY_REJECTED,
        )
    year = int(m.group(1))
    month = int(m.group(2))
    if not (2000 <= year <= 2100) or not (1 <= month <= 12):
        raise CollectorError(
            "BLOCKED_INVALID_MONTH",
            f"Out-of-range calendar month in label: {ym!r}",
            EXIT_POLICY_REJECTED,
        )
    return year, month


def iter_months(start_ym: str, end_ym: str) -> List[str]:
    """Return inclusive chronological list of YYYY-MM strings from start_ym to end_ym."""
    sy, sm = validate_month_label(start_ym)
    ey, em = validate_month_label(end_ym)
    if (sy, sm) > (ey, em):
        raise CollectorError(
            "BLOCKED_INVALID_PERIOD_RANGE",
            f"start_month {start_ym} must be <= end_month {end_ym}",
            EXIT_POLICY_REJECTED,
        )
    out: List[str] = []
    cy, cm = sy, sm
    while (cy, cm) <= (ey, em):
        out.append(f"{cy:04d}-{cm:02d}")
        if cm == 12:
            cy += 1
            cm = 1
        else:
            cm += 1
    return out


def month_bounds_ms(ym: str) -> Tuple[int, int, int]:
    """Return (month_start_ms, month_end_ms_inclusive, next_month_start_ms) in UTC."""
    year, month = validate_month_label(ym)
    _, days_in_month = calendar.monthrange(year, month)
    start_dt = datetime(year, month, 1, 0, 0, 0, tzinfo=timezone.utc)
    next_dt = start_dt + timedelta(days=days_in_month)
    start_ms = int((start_dt - EPOCH_UTC).total_seconds()) * 1000
    next_ms = int((next_dt - EPOCH_UTC).total_seconds()) * 1000
    return start_ms, next_ms - 1, next_ms


def detect_epoch_unit(raw_value: Any, context: str = "timestamp") -> Tuple[int, str]:
    """Classify integer epoch timestamp unit ('s', 'ms', 'us', 'ns_or_unknown')."""
    if isinstance(raw_value, bool):
        raise CollectorError(
            "FAILED_TIMESTAMP_FORMAT",
            f"Boolean timestamp rejected in {context}: {raw_value!r}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    if isinstance(raw_value, int):
        val = raw_value
    elif isinstance(raw_value, str):
        stripped = raw_value.strip()
        if not stripped.isdigit():
            raise CollectorError(
                "FAILED_TIMESTAMP_FORMAT",
                f"Non-integer timestamp in {context}: {raw_value!r}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        val = int(stripped)
    else:
        raise CollectorError(
            "FAILED_TIMESTAMP_FORMAT",
            f"Unsupported timestamp type in {context}: {type(raw_value).__name__}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )

    if val <= 0:
        raise CollectorError(
            "FAILED_TIMESTAMP_FORMAT",
            f"Non-positive timestamp in {context}: {val}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    if 1_000_000_000 <= val < 10_000_000_000:
        return val, "s"
    if 1_000_000_000_000 <= val < 10_000_000_000_000:
        return val, "ms"
    if 1_000_000_000_000_000 <= val < 10_000_000_000_000_000:
        return val, "us"
    return val, "ns_or_unknown"


def validate_epoch_ms(raw_value: Any, context: str, expected_unit: str = "ms") -> int:
    """Validate that raw_value is an integer epoch timestamp matching expected_unit ('ms')."""
    val, unit = detect_epoch_unit(raw_value, context=context)
    if unit != expected_unit:
        raise CollectorError(
            "FAILED_TIMESTAMP_UNIT_MISMATCH",
            f"Expected '{expected_unit}' epoch timestamp in {context}, detected unit='{unit}' value={val}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    return val
