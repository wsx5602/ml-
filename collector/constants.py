"""Immutable governance constants, schema definitions, and exit codes."""

from __future__ import annotations

import re
from typing import Dict, Tuple

COLLECTOR_VERSION = "1.2.0"
CONFIG_SCHEMA_VERSION = "cloud_collector_config_v1"
PREFLIGHT_SCHEMA_VERSION = "cloud_collector_preflight_v1"
CHECKPOINT_SCHEMA_VERSION = "cloud_collector_checkpoint_v1"
MANIFEST_SCHEMA_VERSION = "cloud_collector_manifest_v1"

HARD_ALLOWED_SYMBOLS: Tuple[str, ...] = (
    "BTCUSDT",
    "ETHUSDT",
    "SOLUSDT",
    "BNBUSDT",
    "XRPUSDT",
)
HARD_ALLOWED_STREAMS: Tuple[str, ...] = (
    "exec_15m",
    "mark_1h",
    "funding_settlement",
)
HARD_ALLOWED_HOSTS: Tuple[str, ...] = (
    "data.binance.vision",
    "fapi.binance.com",
)

# Confirmed from non-sealed workspace governance & audit documents:
# - Lower bound: 2021-01-01T00:00:00Z (R30 per_file_audit & DAILY_ML_AND_CLOUD_DATA_READINESS_ADDENDUM.md)
# - Upper exclusive OOS boundary: 2025-10-13T00:00:00Z (W1_STAGE_A_TO_STAGE_B_INPUT_MANIFEST.json)
HARD_ALLOWED_START_UTC = "2021-01-01T00:00:00Z"
HARD_ALLOWED_START_MS = 1609459200000
HARD_OOS_FORBIDDEN_START_UTC = "2025-10-13T00:00:00Z"
HARD_OOS_FORBIDDEN_START_MS = 1760313600000

OOS_FORBIDDEN_DIR_NAME = "".join(("oos", "_", "data"))
FORBIDDEN_PATH_SEGMENTS = frozenset({OOS_FORBIDDEN_DIR_NAME, ".git", ".env"})

VISION_MONTHLY_PATH_RE = re.compile(
    r"^/data/futures/um/monthly/(klines|markPriceKlines)/([A-Z0-9]+)/(15m|1h)/\2-\3-(\d{4}-\d{2})\.zip(\.CHECKSUM)?$"
)
FAPI_READONLY_PATHS = frozenset(
    {
        "/fapi/v1/fundingRate",
        "/fapi/v1/exchangeInfo",
        "/fapi/v1/fundingInfo",
    }
)
FORBIDDEN_AUTH_QUERY_RE = re.compile(r"(api[_-]?key|signature|secret|auth)", re.IGNORECASE)
FORBIDDEN_AUTH_HEADERS = frozenset({"x-mbx-apikey", "authorization"})

HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
SAFE_SINGLE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
MONTH_LABEL_RE = re.compile(r"^(\d{4})-(\d{2})$")

STREAM_TO_INTERVAL_MS: Dict[str, int] = {
    "exec_15m": 900_000,
    "mark_1h": 3_600_000,
}
STREAM_TO_VISION_PATH_SPEC: Dict[str, Tuple[str, str]] = {
    "exec_15m": ("klines", "15m"),
    "mark_1h": ("markPriceKlines", "1h"),
}

SUPPORTED_BINANCE_KLINE_HEADERS: Tuple[Tuple[str, ...], ...] = (
    (
        "open_time",
        "open",
        "high",
        "low",
        "close",
        "volume",
        "close_time",
        "quote_volume",
        "count",
        "taker_buy_base_volume",
        "taker_buy_quote_volume",
        "ignore",
    ),
    (
        "open_time",
        "open",
        "high",
        "low",
        "close",
        "volume",
        "close_time",
        "quote_volume",
        "trades",
        "taker_buy_base_volume",
        "taker_buy_quote_volume",
        "ignore",
    ),
)

STREAM_SCHEMAS: Dict[str, Tuple[str, ...]] = {
    "exec_15m": (
        "open_time_ms",
        "open_time_utc",
        "raw_close_time_ms",
        "logical_close_utc",
        "open",
        "high",
        "low",
        "close",
        "volume",
        "quote_volume",
        "trade_count",
        "taker_buy_base_volume",
        "taker_buy_quote_volume",
    ),
    "mark_1h": (
        "open_time_ms",
        "open_time_utc",
        "raw_close_time_ms",
        "logical_close_utc",
        "open",
        "high",
        "low",
        "close",
    ),
    "funding_settlement": (
        "funding_time_ms",
        "funding_time_utc",
        "funding_rate",
        "settlement_mark_price",
        "observed_interval_hours",
        "rate_type",
    ),
}

EXIT_COMPLETE = 0
EXIT_POLICY_REJECTED = 2
EXIT_INCOMPLETE_DATA = 3
EXIT_RUNTIME_OR_INTEGRITY_ERROR = 4

UNIT_PENDING = "PENDING"
UNIT_VERIFIED_COMPLETE = "VERIFIED_COMPLETE"
UNIT_SKIPPED_PRE_LISTING = "SKIPPED_PRE_LISTING"
UNIT_INCOMPLETE_MISSING_SETTLEMENT_MARK_PRICE = "INCOMPLETE_MISSING_SETTLEMENT_MARK_PRICE"
UNIT_INCOMPLETE_MISSING_STREAM_OR_GAPS = "INCOMPLETE_MISSING_STREAM_OR_GAPS"
UNIT_FAILED_TRANSPORT_OR_RATE_LIMIT = "FAILED_TRANSPORT_OR_RATE_LIMIT"
UNIT_FAILED_CORRUPT_OR_CHECKSUM = "FAILED_CORRUPT_OR_CHECKSUM"
UNIT_FAILED_BUDGET_EXCEEDED = "FAILED_BUDGET_EXCEEDED"
UNIT_FAILED_POLICY_VIOLATION = "FAILED_POLICY_VIOLATION"

TERMINAL_INCOMPLETE_STATUSES = frozenset(
    {
        UNIT_INCOMPLETE_MISSING_SETTLEMENT_MARK_PRICE,
        UNIT_INCOMPLETE_MISSING_STREAM_OR_GAPS,
    }
)
TERMINAL_FAILED_STATUSES = frozenset(
    {
        UNIT_FAILED_TRANSPORT_OR_RATE_LIMIT,
        UNIT_FAILED_CORRUPT_OR_CHECKSUM,
        UNIT_FAILED_BUDGET_EXCEEDED,
        UNIT_FAILED_POLICY_VIOLATION,
    }
)


class CollectorError(Exception):
    """Fail-closed collector exception carrying an error code and deterministic exit code."""

    def __init__(
        self,
        code: str,
        message: str,
        exit_code: int = EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        *,
        bytes_received: int = 0,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code
        self.bytes_received = max(0, int(bytes_received))
