"""Binary archive extraction, schema validation, unit checking, and LF CSV serialization."""

from __future__ import annotations

import csv
import io
import json
import stat
import zipfile
import zlib
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Tuple

from .constants import (
    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
    HEX64_RE,
    SAFE_SINGLE_SEGMENT_RE,
    STREAM_SCHEMAS,
    SUPPORTED_BINANCE_KLINE_HEADERS,
    CollectorError,
)
from .time_utils import format_utc_ms, validate_epoch_ms


def _parse_decimal_gt_zero(raw: str, field_name: str, context: str) -> Decimal:
    try:
        dec = Decimal(raw.strip())
    except InvalidOperation as exc:
        raise CollectorError(
            "FAILED_INVALID_DECIMAL_VALUE",
            f"Non-decimal {field_name}={raw!r} in {context}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        ) from exc
    if not dec.is_finite() or dec <= Decimal("0"):
        raise CollectorError(
            "FAILED_NONPOSITIVE_OR_NONFINITE_VALUE",
            f"Invalid {field_name}={raw!r} in {context}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    return dec


def _parse_decimal_ge_zero(raw: str, field_name: str, context: str) -> Decimal:
    try:
        dec = Decimal(raw.strip())
    except InvalidOperation as exc:
        raise CollectorError(
            "FAILED_INVALID_DECIMAL_VALUE",
            f"Non-decimal {field_name}={raw!r} in {context}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        ) from exc
    if not dec.is_finite() or dec < Decimal("0"):
        raise CollectorError(
            "FAILED_NEGATIVE_OR_NONFINITE_VALUE",
            f"Invalid {field_name}={raw!r} in {context}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    return dec


def _parse_nonneg_int_str(raw: str, field_name: str, context: str) -> int:
    text = raw.strip()
    if not text.isdigit():
        raise CollectorError(
            "FAILED_INVALID_INTEGER_FIELD",
            f"Expected non-negative integer for {field_name}={raw!r} in {context}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    return int(text)


def parse_binance_checksum(raw_bytes: bytes, expected_archive_filename: str) -> str:
    """Parse Binance Vision .CHECKSUM payload and validate SHA-256 hex + filename."""
    try:
        text = raw_bytes.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise CollectorError(
            "FAILED_MALFORMED_CHECKSUM",
            f"Checksum file is not valid UTF-8: {exc}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        ) from exc
    if not text:
        raise CollectorError(
            "FAILED_MALFORMED_CHECKSUM",
            "Empty .CHECKSUM payload.",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise CollectorError(
            "FAILED_MALFORMED_CHECKSUM",
            f"Expected single checksum line, got {len(lines)}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    parts = lines[0].split()
    digest_hex = parts[0]
    if not HEX64_RE.match(digest_hex):
        raise CollectorError(
            "FAILED_MALFORMED_CHECKSUM",
            f"Invalid SHA-256 hex in checksum file: {digest_hex!r}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    if len(parts) >= 2:
        listed_name = parts[-1].lstrip("*")
        if listed_name != expected_archive_filename:
            raise CollectorError(
                "FAILED_CHECKSUM_FILENAME_MISMATCH",
                f"Checksum file lists {listed_name!r}, expected {expected_archive_filename!r}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
    return digest_hex.lower()


def validate_safe_member_name(name: str, label: str = "archive member") -> None:
    """Reject empty, directory traversal, drive letters, and non-single-segment filenames."""
    if (
        not name
        or "/" in name
        or "\\" in name
        or ":" in name
        or ".." in name
        or "\x00" in name
        or not SAFE_SINGLE_SEGMENT_RE.match(name)
    ):
        raise CollectorError(
            "FAILED_UNSAFE_ARCHIVE_MEMBER",
            f"Unsafe {label} name rejected: {name!r}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )


def extract_verified_zip_csv(
    zip_bytes: bytes,
    expected_inner_csv: str,
    max_uncompressed_bytes: int,
) -> bytes:
    """Validate ZIP integrity/CRC/member safety and return bounded decompressed CSV bytes."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes), "r")
    except zipfile.BadZipFile as exc:
        raise CollectorError(
            "FAILED_BAD_ZIP_ARCHIVE",
            f"Corrupt or invalid ZIP archive: {exc}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        ) from exc

    with zf:
        infos = zf.infolist()
        if len(infos) != 1:
            raise CollectorError(
                "FAILED_UNEXPECTED_ZIP_MEMBER_COUNT",
                f"Expected exactly 1 ZIP member, got {len(infos)}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        info = infos[0]
        if info.is_dir():
            raise CollectorError(
                "FAILED_UNSAFE_ARCHIVE_MEMBER",
                f"Directory entry in ZIP rejected: {info.filename!r}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise CollectorError(
                "FAILED_UNSAFE_ARCHIVE_MEMBER",
                f"Symlink ZIP member rejected: {info.filename!r}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        validate_safe_member_name(info.filename, "ZIP member")
        if info.filename != expected_inner_csv:
            raise CollectorError(
                "FAILED_ZIP_MEMBER_NAME_MISMATCH",
                f"Expected ZIP member {expected_inner_csv!r}, got {info.filename!r}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        if info.file_size > max_uncompressed_bytes:
            raise CollectorError(
                "FAILED_UNCOMPRESSED_SIZE_LIMIT_EXCEEDED",
                f"ZIP header file_size={info.file_size} exceeds cap {max_uncompressed_bytes}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        out = bytearray()
        try:
            with zf.open(info, "r") as member_fp:
                while True:
                    chunk = member_fp.read(65536)
                    if not chunk:
                        break
                    out.extend(chunk)
                    if len(out) > max_uncompressed_bytes:
                        raise CollectorError(
                            "FAILED_UNCOMPRESSED_SIZE_LIMIT_EXCEEDED",
                            f"Decompressed CSV exceeded cap {max_uncompressed_bytes}",
                            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                        )
        except zipfile.BadZipFile as exc:
            raise CollectorError(
                "FAILED_ZIP_CRC_ERROR",
                f"ZIP CRC/stream verification failed for {info.filename!r}: {exc}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            ) from exc
        raw_out = bytes(out)
        if (zlib.crc32(raw_out) & 0xFFFFFFFF) != (info.CRC & 0xFFFFFFFF):
            raise CollectorError(
                "FAILED_ZIP_CRC_ERROR",
                f"ZIP CRC-32 mismatch for {info.filename!r}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        return raw_out


@dataclass
class KlineParseAudit:
    """Result of parsing and auditing a monthly kline CSV archive."""

    rows: List[Dict[str, Any]]
    header_variant: str
    raw_rows_count: int
    usable_rows_count: int
    pre_listing_excluded_count: int
    oos_boundary_excluded_count: int
    duplicate_count: int
    non_monotonic_count: int
    missing_count: int
    out_of_requested_window_count: int = 0
    identical_duplicate_count: int = 0
    conflicting_duplicate_count: int = 0
    missing_samples: List[str] = field(default_factory=list)
    duplicate_samples: List[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return (
            self.usable_rows_count > 0
            and self.duplicate_count == 0
            and self.conflicting_duplicate_count == 0
            and self.non_monotonic_count == 0
            and self.missing_count == 0
        )


def parse_kline_csv(
    raw_csv_bytes: bytes,
    *,
    stream: str,
    interval_ms: int,
    month_start_ms: int,
    month_end_ms: int,
    effective_start_ms: int,
    requested_start_ms: int,
    requested_end_exclusive_ms: int,
    is_listing_month: bool,
    oos_forbidden_start_ms: int,
    expected_timestamp_unit: str,
    context: str,
) -> KlineParseAudit:
    """Parse Binance 12-column kline CSV, validate unit/schema/bounds, and audit gaps & duplicates."""
    try:
        text = raw_csv_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CollectorError("FAILED_CSV_ENCODING", f"Non-UTF-8 CSV in {context}: {exc}", EXIT_RUNTIME_OR_INTEGRITY_ERROR) from exc

    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        raise CollectorError("FAILED_EMPTY_ARCHIVE_CSV", f"Empty CSV in {context}", EXIT_RUNTIME_OR_INTEGRITY_ERROR)

    rows = list(csv.reader(lines))
    first = [c.strip() for c in rows[0]]
    if len(first) != 12:
        raise CollectorError(
            "FAILED_UNSUPPORTED_ARCHIVE_SCHEMA",
            f"Expected 12 columns in {context}, got {len(first)}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )

    header_variant = "headerless"
    start_idx = 0
    if any(ch.isalpha() for ch in first[0]) and not first[0].isdigit():
        normalized = tuple(c.lower() for c in first)
        if normalized not in SUPPORTED_BINANCE_KLINE_HEADERS:
            raise CollectorError(
                "FAILED_UNSUPPORTED_ARCHIVE_SCHEMA",
                f"Unsupported CSV header in {context}: {first}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        header_variant = f"header:{normalized[8]}"
        start_idx = 1

    if start_idx >= len(rows):
        raise CollectorError("FAILED_EMPTY_ARCHIVE_CSV", f"Header-only CSV with 0 rows in {context}", EXIT_RUNTIME_OR_INTEGRITY_ERROR)

    usable_rows: List[Dict[str, Any]] = []
    pre_listing_excluded = 0
    oos_boundary_excluded = 0
    out_of_requested_window = 0
    duplicate_count = 0
    identical_duplicate_count = 0
    conflicting_duplicate_count = 0
    non_monotonic_count = 0
    missing_count = 0
    missing_samples: List[str] = []
    duplicate_samples: List[str] = []

    seen_by_open: Dict[int, Tuple[Any, ...]] = {}
    prev_open_ms: Optional[int] = None
    raw_rows_count = 0

    for offset, cols in enumerate(rows[start_idx:], start=start_idx + 1):
        if len(cols) != 12:
            raise CollectorError(
                "FAILED_UNSUPPORTED_ARCHIVE_SCHEMA",
                f"Row {offset} has {len(cols)} != 12 columns in {context}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        raw_rows_count += 1
        open_ms = validate_epoch_ms(cols[0], f"{context}:row{offset}.open_time", expected_timestamp_unit)
        close_ms = validate_epoch_ms(cols[6], f"{context}:row{offset}.close_time", expected_timestamp_unit)

        if open_ms % interval_ms != 0:
            raise CollectorError(
                "FAILED_TIMESTAMP_GRID_MISALIGNMENT",
                f"open_time {open_ms} not aligned to interval_ms={interval_ms} in {context}:row{offset}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        if close_ms != open_ms + interval_ms - 1:
            raise CollectorError(
                "FAILED_CLOSE_TIME_INTERVAL_MISMATCH",
                f"close_time {close_ms} != open_time + interval - 1 in {context}:row{offset}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        logical_close_ms = open_ms + interval_ms
        if open_ms >= oos_forbidden_start_ms or close_ms >= oos_forbidden_start_ms or logical_close_ms >= oos_forbidden_start_ms:
            raise CollectorError(
                "FAILED_OOS_CONTAMINATION_IN_PAYLOAD",
                (
                    f"Bar open_time={format_utc_ms(open_ms)} / close_time={format_utc_ms(close_ms)} / "
                    f"logical_close={format_utc_ms(logical_close_ms)} touches or crosses forbidden OOS start "
                    f"{oos_forbidden_start_ms} in {context}; post-download OOS filtering is forbidden."
                ),
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        if not (month_start_ms <= open_ms <= month_end_ms):
            raise CollectorError(
                "FAILED_ROW_OUTSIDE_REQUESTED_MONTH",
                f"Row open_time {format_utc_ms(open_ms)} outside month [{format_utc_ms(month_start_ms)}, {format_utc_ms(month_end_ms)}] in {context}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )

        o_dec = _parse_decimal_gt_zero(cols[1], "open", f"{context}:row{offset}")
        h_dec = _parse_decimal_gt_zero(cols[2], "high", f"{context}:row{offset}")
        l_dec = _parse_decimal_gt_zero(cols[3], "low", f"{context}:row{offset}")
        c_dec = _parse_decimal_gt_zero(cols[4], "close", f"{context}:row{offset}")
        if h_dec < max(o_dec, c_dec, l_dec) or l_dec > min(o_dec, c_dec, h_dec):
            raise CollectorError(
                "FAILED_INVALID_OHLC_ENVELOPE",
                f"OHLC envelope violated in {context}:row{offset}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )

        if open_ms < effective_start_ms:
            pre_listing_excluded += 1
            continue
        if open_ms < requested_start_ms or open_ms >= requested_end_exclusive_ms:
            out_of_requested_window += 1
            continue

        row_dict: Dict[str, Any] = {
            "open_time_ms": open_ms,
            "open_time_utc": format_utc_ms(open_ms),
            "raw_close_time_ms": close_ms,
            "logical_close_utc": format_utc_ms(logical_close_ms),
            "open": str(o_dec),
            "high": str(h_dec),
            "low": str(l_dec),
            "close": str(c_dec),
        }
        if stream == "exec_15m":
            vol_dec = _parse_decimal_ge_zero(cols[5], "volume", f"{context}:row{offset}")
            qvol_dec = _parse_decimal_ge_zero(cols[7], "quote_volume", f"{context}:row{offset}")
            t_cnt = _parse_nonneg_int_str(cols[8], "trade_count", f"{context}:row{offset}")
            tb_base = _parse_decimal_ge_zero(cols[9], "taker_buy_base_volume", f"{context}:row{offset}")
            tb_quote = _parse_decimal_ge_zero(cols[10], "taker_buy_quote_volume", f"{context}:row{offset}")
            row_dict.update(
                {
                    "volume": str(vol_dec),
                    "quote_volume": str(qvol_dec),
                    "trade_count": t_cnt,
                    "taker_buy_base_volume": str(tb_base),
                    "taker_buy_quote_volume": str(tb_quote),
                }
            )

        row_fingerprint = tuple(row_dict[k] for k in sorted(row_dict.keys()))
        if open_ms in seen_by_open:
            duplicate_count += 1
            if seen_by_open[open_ms] == row_fingerprint:
                identical_duplicate_count += 1
                if len(duplicate_samples) < 10:
                    duplicate_samples.append(f"identical:{format_utc_ms(open_ms)}")
            else:
                conflicting_duplicate_count += 1
                if len(duplicate_samples) < 10:
                    duplicate_samples.append(f"conflict:{format_utc_ms(open_ms)}")
        else:
            seen_by_open[open_ms] = row_fingerprint
            if prev_open_ms is not None:
                if open_ms < prev_open_ms:
                    non_monotonic_count += 1
                    if len(duplicate_samples) < 10:
                        duplicate_samples.append(f"non_mono:{format_utc_ms(open_ms)}<{format_utc_ms(prev_open_ms)}")
                elif open_ms > prev_open_ms + interval_ms:
                    gap_bars = ((open_ms - prev_open_ms) // interval_ms) - 1
                    missing_count += gap_bars
                    if len(missing_samples) < 10:
                        missing_samples.append(f"{format_utc_ms(prev_open_ms + interval_ms)}..{format_utc_ms(open_ms - interval_ms)}({gap_bars})")

            if prev_open_ms is None or open_ms > prev_open_ms:
                prev_open_ms = open_ms
            usable_rows.append(row_dict)

    # Boundary coverage audit (no fabrication of missing rows!)
    expected_window_start_ms = max(month_start_ms, requested_start_ms)
    expected_first_aligned_ms = ((max(expected_window_start_ms, effective_start_ms) + interval_ms - 1) // interval_ms) * interval_ms
    expected_last_open_ms = min(month_end_ms + 1, requested_end_exclusive_ms, oos_forbidden_start_ms) - interval_ms
    if expected_last_open_ms >= expected_first_aligned_ms:
        if not usable_rows:
            missing_count += ((expected_last_open_ms - expected_first_aligned_ms) // interval_ms) + 1
        else:
            first_open_ms = usable_rows[0]["open_time_ms"]
            last_open_ms = usable_rows[-1]["open_time_ms"]
            if not is_listing_month and first_open_ms > expected_first_aligned_ms:
                start_gap = (first_open_ms - expected_first_aligned_ms) // interval_ms
                missing_count += start_gap
                if len(missing_samples) < 10:
                    missing_samples.append(f"month_start_gap:{format_utc_ms(expected_first_aligned_ms)}..{format_utc_ms(first_open_ms - interval_ms)}({start_gap})")
            elif is_listing_month and first_open_ms > expected_first_aligned_ms:
                list_gap = (first_open_ms - expected_first_aligned_ms) // interval_ms
                missing_count += list_gap
                if len(missing_samples) < 10:
                    missing_samples.append(f"listing_start_gap:{format_utc_ms(expected_first_aligned_ms)}({list_gap})")
            if last_open_ms < expected_last_open_ms:
                end_gap = (expected_last_open_ms - last_open_ms) // interval_ms
                missing_count += end_gap
                if len(missing_samples) < 10:
                    missing_samples.append(f"month_end_gap:{format_utc_ms(last_open_ms + interval_ms)}..{format_utc_ms(expected_last_open_ms)}({end_gap})")

    return KlineParseAudit(
        rows=usable_rows,
        header_variant=header_variant,
        raw_rows_count=raw_rows_count,
        usable_rows_count=len(usable_rows),
        pre_listing_excluded_count=pre_listing_excluded,
        oos_boundary_excluded_count=oos_boundary_excluded,
        duplicate_count=duplicate_count,
        non_monotonic_count=non_monotonic_count,
        missing_count=missing_count,
        out_of_requested_window_count=out_of_requested_window,
        identical_duplicate_count=identical_duplicate_count,
        conflicting_duplicate_count=conflicting_duplicate_count,
        missing_samples=missing_samples,
        duplicate_samples=duplicate_samples,
    )


@dataclass
class FundingParseAudit:
    """Result of parsing and auditing monthly /fapi/v1/fundingRate REST pages."""

    events: List[Dict[str, Any]]
    raw_events_count: int
    usable_events_count: int
    missing_settlement_mark_price_count: int
    missing_settlement_mark_price_samples: List[str] = field(default_factory=list)
    duplicate_count: int = 0
    page_boundary_identical_duplicate_count: int = 0
    intra_page_identical_duplicate_count: int = 0
    conflicting_duplicate_count: int = 0
    conflicting_duplicate_samples: List[str] = field(default_factory=list)
    non_monotonic_count: int = 0
    missing_gap_count: int = 0
    missing_gap_samples: List[str] = field(default_factory=list)
    duplicate_samples: List[str] = field(default_factory=list)
    subsecond_offset_count: int = 0
    non_8h_short_interval_count: int = 0
    irregular_interval_count: int = 0
    observed_interval_hours_min: Optional[float] = None
    observed_interval_hours_max: Optional[float] = None
    observed_interval_hours_set: List[float] = field(default_factory=list)
    observed_interval_histogram: Dict[str, int] = field(default_factory=dict)
    interval_warnings: List[str] = field(default_factory=list)
    pre_listing_excluded_count: int = 0
    out_of_requested_window_count: int = 0
    truncated_by_page_cap: bool = False
    first_populated_settlement_mark_utc: Optional[str] = None

    @property
    def has_missing_settlement_mark_price(self) -> bool:
        return self.missing_settlement_mark_price_count > 0

    @property
    def has_conflicting_duplicate(self) -> bool:
        return self.conflicting_duplicate_count > 0

    @property
    def is_clean(self) -> bool:
        return (
            self.usable_events_count > 0
            and not self.has_missing_settlement_mark_price
            and not self.has_conflicting_duplicate
            and self.non_monotonic_count == 0
            and self.missing_gap_count == 0
            and not self.truncated_by_page_cap
        )


def parse_funding_pages(
    raw_pages: List[bytes],
    *,
    symbol: str,
    month_start_ms: int,
    month_end_ms: int,
    effective_start_ms: int,
    requested_start_ms: int,
    requested_end_exclusive_ms: int,
    is_listing_month: bool,
    oos_forbidden_start_ms: int,
    anomalous_funding_interval_warning_hours: float,
    expected_timestamp_unit: str,
    truncated_by_page_cap: bool,
    context: str,
) -> FundingParseAudit:
    """Parse raw JSON pages from /fapi/v1/fundingRate without assuming a fixed 8h grid."""
    del is_listing_month  # Irregular funding stream never fabricates missing start gaps on a fixed 8h grid.
    events: List[Dict[str, Any]] = []
    raw_events_count = 0
    missing_mp_count = 0
    missing_mp_samples: List[str] = []
    duplicate_count = 0
    page_boundary_identical_dup = 0
    intra_page_identical_dup = 0
    conflicting_dup = 0
    conflicting_dup_samples: List[str] = []
    non_monotonic_count = 0
    missing_gap_count = 0
    missing_gap_samples: List[str] = []
    duplicate_samples: List[str] = []
    subsecond_count = 0
    non_8h_short_count = 0
    irregular_interval_count = 0
    observed_intervals_seen = set()
    observed_histogram: Dict[str, int] = {}
    interval_warnings: List[str] = []
    pre_listing_excluded = 0
    out_of_requested_window = 0
    first_populated_mp_ms: Optional[int] = None

    seen_by_ft: Dict[int, Tuple[int, Tuple[str, str, str]]] = {}
    prev_ts_ms: Optional[int] = None
    warn_interval_ms = int(round(anomalous_funding_interval_warning_hours * 3_600_000))

    for page_idx, raw_page in enumerate(raw_pages, start=1):
        try:
            payload = json.loads(raw_page.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CollectorError(
                "FAILED_INVALID_REST_JSON",
                f"Invalid JSON in {context} page {page_idx}: {exc}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            ) from exc
        if not isinstance(payload, list):
            raise CollectorError(
                "FAILED_UNEXPECTED_REST_PAYLOAD_TYPE",
                f"Expected JSON array in {context} page {page_idx}, got {type(payload).__name__}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )

        for item_idx, item in enumerate(payload):
            if not isinstance(item, dict):
                raise CollectorError(
                    "FAILED_UNEXPECTED_REST_PAYLOAD_TYPE",
                    f"Expected JSON object at {context} page {page_idx} row {item_idx}",
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                )
            raw_events_count += 1
            if item.get("symbol") != symbol:
                raise CollectorError(
                    "FAILED_WRONG_SYMBOL_IN_FUNDING_RESPONSE",
                    f"Expected symbol {symbol!r}, got {item.get('symbol')!r} in {context}",
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                )
            ft_ms = validate_epoch_ms(item.get("fundingTime"), f"{context}:p{page_idx}r{item_idx}.fundingTime", expected_timestamp_unit)
            if ft_ms >= oos_forbidden_start_ms:
                raise CollectorError(
                    "FAILED_OOS_CONTAMINATION_IN_PAYLOAD",
                    f"fundingTime={ft_ms} ({format_utc_ms(ft_ms)}) >= forbidden OOS cutoff in {context}",
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                )
            if not (month_start_ms <= ft_ms <= month_end_ms):
                raise CollectorError(
                    "FAILED_FUNDING_TIMESTAMP_OUT_OF_MONTH",
                    f"fundingTime={format_utc_ms(ft_ms)} outside requested month bounds in {context}",
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                )
            if ft_ms < effective_start_ms:
                pre_listing_excluded += 1
                continue
            if ft_ms < requested_start_ms or ft_ms >= requested_end_exclusive_ms:
                out_of_requested_window += 1
                continue

            raw_rate = item.get("fundingRate")
            if isinstance(raw_rate, bool) or raw_rate is None or not str(raw_rate).strip():
                raise CollectorError(
                    "FAILED_MISSING_FUNDING_RATE",
                    f"Missing fundingRate at {format_utc_ms(ft_ms)} in {context}",
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                )
            try:
                rate_dec = Decimal(str(raw_rate).strip())
            except InvalidOperation as exc:
                raise CollectorError(
                    "FAILED_INVALID_FUNDING_RATE",
                    f"Non-decimal fundingRate={raw_rate!r} in {context}",
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                ) from exc
            if not rate_dec.is_finite():
                raise CollectorError(
                    "FAILED_INVALID_FUNDING_RATE",
                    f"Non-finite fundingRate={raw_rate!r} in {context}",
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                )

            # Strict settlement mark price rule: NEVER substitute or zero-fill!
            mp_str: Optional[str] = None
            raw_mp = item.get("markPrice") if "markPrice" in item else None
            if isinstance(raw_mp, bool) or raw_mp is None or not str(raw_mp).strip():
                missing_mp_count += 1
                if len(missing_mp_samples) < 10:
                    missing_mp_samples.append(format_utc_ms(ft_ms))
            else:
                try:
                    mp_dec = Decimal(str(raw_mp).strip())
                    if not mp_dec.is_finite() or mp_dec <= Decimal("0"):
                        missing_mp_count += 1
                        if len(missing_mp_samples) < 10:
                            missing_mp_samples.append(f"{format_utc_ms(ft_ms)}(invalid:{raw_mp})")
                    else:
                        mp_str = str(mp_dec)
                        if first_populated_mp_ms is None or ft_ms < first_populated_mp_ms:
                            first_populated_mp_ms = ft_ms
                except InvalidOperation:
                    missing_mp_count += 1
                    if len(missing_mp_samples) < 10:
                        missing_mp_samples.append(f"{format_utc_ms(ft_ms)}(non_decimal:{raw_mp})")

            mp_text = mp_str if mp_str is not None else ""
            rate_type_text = "" if item.get("rateType") is None else str(item.get("rateType"))
            event_fingerprint = (str(rate_dec), mp_text, rate_type_text)

            if ft_ms in seen_by_ft:
                first_page_idx, prev_fp = seen_by_ft[ft_ms]
                duplicate_count += 1
                if event_fingerprint == prev_fp:
                    if first_page_idx != page_idx:
                        page_boundary_identical_dup += 1
                        if len(duplicate_samples) < 10:
                            duplicate_samples.append(f"page_overlap_identical:{format_utc_ms(ft_ms)}")
                    else:
                        intra_page_identical_dup += 1
                        if len(duplicate_samples) < 10:
                            duplicate_samples.append(f"intra_page_identical:{format_utc_ms(ft_ms)}")
                    continue
                conflicting_dup += 1
                conflict_msg = (
                    f"conflict@{format_utc_ms(ft_ms)}:p{first_page_idx}={prev_fp} vs p{page_idx}={event_fingerprint}"
                )
                if len(conflicting_dup_samples) < 10:
                    conflicting_dup_samples.append(conflict_msg)
                if len(duplicate_samples) < 10:
                    duplicate_samples.append(conflict_msg)
                continue

            seen_by_ft[ft_ms] = (page_idx, event_fingerprint)

            if ft_ms % 1000 != 0:
                subsecond_count += 1

            obs_hours_str = ""
            if prev_ts_ms is not None:
                if ft_ms < prev_ts_ms:
                    non_monotonic_count += 1
                    if len(duplicate_samples) < 10:
                        duplicate_samples.append(f"non_mono:{format_utc_ms(ft_ms)}<{format_utc_ms(prev_ts_ms)}")
                else:
                    delta_ms = ft_ms - prev_ts_ms
                    obs_h = round(delta_ms / 3_600_000.0, 6)
                    obs_h_key = f"{round(delta_ms / 3_600_000.0, 3):g}"
                    obs_hours_str = f"{obs_h:g}"
                    observed_intervals_seen.add(round(delta_ms / 3_600_000.0, 3))
                    observed_histogram[obs_h_key] = observed_histogram.get(obs_h_key, 0) + 1
                    if delta_ms < int(7.95 * 3_600_000):
                        non_8h_short_count += 1
                    if not (int(7.95 * 3_600_000) <= delta_ms <= int(8.05 * 3_600_000)):
                        irregular_interval_count += 1
                    if delta_ms > warn_interval_ms and len(interval_warnings) < 10:
                        interval_warnings.append(
                            f"long_interval:{format_utc_ms(prev_ts_ms)}->{format_utc_ms(ft_ms)}({obs_h}h)"
                        )

            if prev_ts_ms is None or ft_ms > prev_ts_ms:
                prev_ts_ms = ft_ms

            events.append(
                {
                    "funding_time_ms": ft_ms,
                    "funding_time_utc": format_utc_ms(ft_ms),
                    "funding_rate": str(rate_dec),
                    "settlement_mark_price": mp_text,
                    "observed_interval_hours": obs_hours_str,
                    "rate_type": rate_type_text,
                }
            )

    if truncated_by_page_cap:
        missing_gap_count += 1
        if len(missing_gap_samples) < 10:
            missing_gap_samples.append("truncated_by_max_funding_pages_per_month")

    if not events:
        missing_gap_count += 1
        if len(missing_gap_samples) < 10:
            missing_gap_samples.append("empty_funding_events_for_active_month")

    sorted_intervals = sorted(observed_intervals_seen)
    return FundingParseAudit(
        events=events,
        raw_events_count=raw_events_count,
        usable_events_count=len(events),
        missing_settlement_mark_price_count=missing_mp_count,
        missing_settlement_mark_price_samples=missing_mp_samples,
        duplicate_count=duplicate_count,
        page_boundary_identical_duplicate_count=page_boundary_identical_dup,
        intra_page_identical_duplicate_count=intra_page_identical_dup,
        conflicting_duplicate_count=conflicting_dup,
        conflicting_duplicate_samples=conflicting_dup_samples,
        non_monotonic_count=non_monotonic_count,
        missing_gap_count=missing_gap_count,
        missing_gap_samples=missing_gap_samples,
        duplicate_samples=duplicate_samples,
        subsecond_offset_count=subsecond_count,
        non_8h_short_interval_count=non_8h_short_count,
        irregular_interval_count=irregular_interval_count,
        observed_interval_hours_min=sorted_intervals[0] if sorted_intervals else None,
        observed_interval_hours_max=sorted_intervals[-1] if sorted_intervals else None,
        observed_interval_hours_set=sorted_intervals,
        observed_interval_histogram=observed_histogram,
        interval_warnings=interval_warnings,
        pre_listing_excluded_count=pre_listing_excluded,
        out_of_requested_window_count=out_of_requested_window,
        truncated_by_page_cap=truncated_by_page_cap,
        first_populated_settlement_mark_utc=format_utc_ms(first_populated_mp_ms) if first_populated_mp_ms is not None else None,
    )


def serialize_rows_to_csv_lf(stream: str, rows: List[Dict[str, Any]]) -> str:
    """Serialize normalized rows into UTF-8 LF-only CSV conforming to STREAM_SCHEMAS."""
    columns = STREAM_SCHEMAS[stream]
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow([row[col] for col in columns])
    return buf.getvalue()
