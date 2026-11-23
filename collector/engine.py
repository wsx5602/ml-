"""Core monthly-chunked collector engine: preflight, collect/resume, verify, and bundle export."""

from __future__ import annotations

import csv
import datetime as _dt
import io
import json
import math
import os
import sys
import tarfile
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .config import CollectorConfig, load_and_validate_config
from .constants import (
    CHECKPOINT_SCHEMA_VERSION,
    COLLECTOR_VERSION,
    EXIT_COMPLETE,
    EXIT_INCOMPLETE_DATA,
    EXIT_POLICY_REJECTED,
    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
    HARD_OOS_FORBIDDEN_START_MS,
    HARD_OOS_FORBIDDEN_START_UTC,
    HEX64_RE,
    MANIFEST_SCHEMA_VERSION,
    PREFLIGHT_SCHEMA_VERSION,
    STREAM_SCHEMAS,
    STREAM_TO_INTERVAL_MS,
    STREAM_TO_VISION_PATH_SPEC,
    TERMINAL_FAILED_STATUSES,
    TERMINAL_INCOMPLETE_STATUSES,
    UNIT_FAILED_BUDGET_EXCEEDED,
    UNIT_FAILED_CORRUPT_OR_CHECKSUM,
    UNIT_FAILED_POLICY_VIOLATION,
    UNIT_FAILED_TRANSPORT_OR_RATE_LIMIT,
    UNIT_INCOMPLETE_MISSING_SETTLEMENT_MARK_PRICE,
    UNIT_INCOMPLETE_MISSING_STREAM_OR_GAPS,
    UNIT_PENDING,
    UNIT_SKIPPED_PRE_LISTING,
    UNIT_VERIFIED_COMPLETE,
    CollectorError,
)
from .io_utils import (
    atomic_write_bytes,
    atomic_write_json,
    atomic_write_utf8_lf,
    compute_directory_bytes,
    resolve_safe_rel_posix,
    sha256_bytes_raw,
    sha256_file_from_disk,
    validate_safe_dir_path,
)
from .parsers import (
    extract_verified_zip_csv,
    parse_binance_checksum,
    parse_funding_pages,
    parse_kline_csv,
    serialize_rows_to_csv_lf,
)
from .time_utils import format_utc_ms, month_bounds_ms, parse_iso_utc_to_ms, validate_epoch_ms
from .transport import (
    BudgetTracker,
    RateLimitedClient,
    TransportCallable,
    validate_request_url,
)

OFFICIAL_SOURCES_METADATA: Dict[str, Any] = {
    "binance_usds_m_futures_docs": "https://developers.binance.com/docs/derivatives/usds-margined-futures/general-info",
    "exchange_info_endpoint": "https://developers.binance.com/docs/derivatives/usds-margined-futures/market-data/rest-api/Exchange-Information",
    "klines_endpoint": "https://developers.binance.com/docs/derivatives/usds-margined-futures/market-data/rest-api/Kline-Candlestick-Data",
    "mark_price_klines_endpoint": "https://developers.binance.com/docs/derivatives/usds-margined-futures/market-data/rest-api/Mark-Price-Kline-Candlestick-Data",
    "funding_rate_endpoint": "https://developers.binance.com/docs/derivatives/usds-margined-futures/market-data/rest-api/Get-Funding-Rate-History",
    "funding_info_endpoint": "https://developers.binance.com/docs/derivatives/usds-margined-futures/market-data/rest-api/Get-Funding-Rate-Info",
    "binance_public_data_repo": "https://github.com/binance/binance-public-data",
    "binance_vision_base": "https://data.binance.vision",
    "binance_vision_terms": "https://data.binance.vision/Binance_Vision-Terms_of_Use.pdf",
}


def _utc_now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _unit_key(symbol: str, stream: str, month: str) -> str:
    return f"{symbol}|{stream}|{month}"


@dataclass(frozen=True)
class PlannedUnit:
    """Single deterministic monthly work unit for (symbol, stream, YYYY-MM)."""

    unit_key: str
    symbol: str
    stream: str
    month: str
    month_start_ms: int
    month_end_ms: int
    effective_end_ms: int
    planned_urls: Tuple[str, ...]
    archive_filename: Optional[str] = None
    checksum_filename: Optional[str] = None
    inner_csv_filename: Optional[str] = None


def _build_work_plan(config: CollectorConfig) -> Tuple[List[PlannedUnit], List[str]]:
    """Build deterministic planned work units and pre-validate every URL before transport."""
    units: List[PlannedUnit] = []
    meta_urls: List[str] = []
    if config.fetch_exchange_metadata:
        for ep in ("/fapi/v1/exchangeInfo", "/fapi/v1/fundingInfo"):
            url = f"{config.fapi_base_url}{ep}"
            validate_request_url(
                url,
                allowed_hosts=config.allowed_hosts,
                allowed_symbols=config.allowed_symbols,
                allowed_start_ms=config.allowed_start_ms,
                oos_forbidden_start_ms=config.oos_forbidden_start_ms,
            )
            meta_urls.append(url)

    for symbol in config.symbols:
        for stream in config.streams:
            for month in config.months:
                m_start_ms, m_end_ms, _m_next_ms = month_bounds_ms(month)
                effective_end_ms = min(m_end_ms, config.requested_end_exclusive_ms - 1, config.oos_forbidden_start_ms - 1)
                ukey = _unit_key(symbol, stream, month)
                if stream in STREAM_TO_VISION_PATH_SPEC:
                    ds_type, interval = STREAM_TO_VISION_PATH_SPEC[stream]
                    archive_fn = f"{symbol}-{interval}-{month}.zip"
                    checksum_fn = f"{archive_fn}.CHECKSUM"
                    inner_csv = f"{symbol}-{interval}-{month}.csv"
                    archive_url = f"{config.vision_base_url}/data/futures/um/monthly/{ds_type}/{symbol}/{interval}/{archive_fn}"
                    checksum_url = f"{archive_url}.CHECKSUM"
                    for u in (checksum_url, archive_url):
                        validate_request_url(
                            u,
                            allowed_hosts=config.allowed_hosts,
                            allowed_symbols=config.allowed_symbols,
                            allowed_start_ms=config.allowed_start_ms,
                            oos_forbidden_start_ms=config.oos_forbidden_start_ms,
                        )
                    units.append(
                        PlannedUnit(
                            unit_key=ukey,
                            symbol=symbol,
                            stream=stream,
                            month=month,
                            month_start_ms=m_start_ms,
                            month_end_ms=m_end_ms,
                            effective_end_ms=effective_end_ms,
                            planned_urls=(checksum_url, archive_url),
                            archive_filename=archive_fn,
                            checksum_filename=checksum_fn,
                            inner_csv_filename=inner_csv,
                        )
                    )
                else:
                    funding_start_ms = max(m_start_ms, config.requested_start_ms)
                    query = urllib.parse.urlencode(
                        {
                            "symbol": symbol,
                            "startTime": funding_start_ms,
                            "endTime": effective_end_ms,
                            "limit": config.funding_page_limit,
                        }
                    )
                    funding_url = f"{config.fapi_base_url}/fapi/v1/fundingRate?{query}"
                    validate_request_url(
                        funding_url,
                        allowed_hosts=config.allowed_hosts,
                        allowed_symbols=config.allowed_symbols,
                        allowed_start_ms=config.allowed_start_ms,
                        oos_forbidden_start_ms=config.oos_forbidden_start_ms,
                    )
                    units.append(
                        PlannedUnit(
                            unit_key=ukey,
                            symbol=symbol,
                            stream=stream,
                            month=month,
                            month_start_ms=m_start_ms,
                            month_end_ms=m_end_ms,
                            effective_end_ms=effective_end_ms,
                            planned_urls=(funding_url,),
                        )
                    )
    return units, meta_urls


def run_preflight(config_path: str | Path, out_dir: Optional[str | Path] = None) -> Tuple[int, Dict[str, Any]]:
    """Run strictly offline config, boundary, URL allowlist, and budget preflight check."""
    config = load_and_validate_config(config_path)
    units, meta_urls = _build_work_plan(config)

    kline_units = sum(1 for u in units if u.stream in STREAM_TO_VISION_PATH_SPEC)
    funding_units = sum(1 for u in units if u.stream == "funding_settlement")
    min_funding_pages_per_month = 1 if config.funding_page_limit >= 93 else ((93 + config.funding_page_limit - 1) // config.funding_page_limit)
    est_min_requests = len(meta_urls) + (kline_units * 2) + (funding_units * min_funding_pages_per_month)
    est_worst_requests = len(meta_urls) + (kline_units * 2) + (funding_units * config.max_funding_pages_per_month)

    if est_min_requests > config.max_http_requests:
        raise CollectorError(
            "BLOCKED_INSUFFICIENT_HTTP_BUDGET",
            f"Minimum required HTTP requests ({est_min_requests}) exceeds budgets.max_http_requests ({config.max_http_requests}).",
            EXIT_POLICY_REJECTED,
        )

    out_dir_checked: Optional[str] = None
    if out_dir is not None:
        safe_out = validate_safe_dir_path(str(out_dir), label="preflight out_dir")
        out_dir_checked = str(safe_out)

    report: Dict[str, Any] = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "collector_version": COLLECTOR_VERSION,
        "status": "PREFLIGHT_PASS",
        "exit_code": EXIT_COMPLETE,
        "network_requests_executed": 0,
        "checked_at_utc": _utc_now_iso(),
        "config_path": config.config_path,
        "config_sha256": config.config_sha256,
        "run_id": config.run_id,
        "mode_label": config.mode_label,
        "period": {
            "start_month": config.start_month,
            "end_month": config.end_month,
            "month_count": len(config.months),
            "requested_start_utc": config.requested_start_utc,
            "requested_end_exclusive_utc": config.requested_end_exclusive_utc,
            "allowed_start_utc": config.allowed_start_utc,
            "oos_forbidden_start_utc": config.oos_forbidden_start_utc,
        },
        "universe_symbols": list(config.symbols),
        "streams": list(config.streams),
        "allowed_hosts": list(config.allowed_hosts),
        "planned_units_count": len(units),
        "kline_archive_units_count": kline_units,
        "funding_units_count": funding_units,
        "metadata_urls": meta_urls,
        "estimated_min_http_requests": est_min_requests,
        "estimated_worst_case_http_requests": est_worst_requests,
        "configured_budgets": {
            "max_http_requests": config.max_http_requests,
            "max_compressed_download_bytes": config.max_compressed_download_bytes,
            "max_single_response_bytes": config.max_single_response_bytes,
            "max_single_uncompressed_bytes": config.max_single_uncompressed_bytes,
            "max_total_storage_bytes": config.max_total_storage_bytes,
            "max_wall_time_seconds": config.max_wall_time_seconds,
            "budget_rationale": config.budget_rationale,
        },
        "planned_unit_samples": [
            {
                "unit_key": u.unit_key,
                "symbol": u.symbol,
                "stream": u.stream,
                "month": u.month,
                "planned_urls": list(u.planned_urls),
            }
            for u in units[:10]
        ],
    }

    if out_dir is not None:
        safe_out_path = Path(out_dir_checked)  # type: ignore[arg-type]
        safe_out_path.mkdir(parents=True, exist_ok=True)
        report_path = safe_out_path / "preflight_report.json"
        r_sha, r_bytes = atomic_write_json(report_path, report, allow_overwrite=True)
        report["preflight_report_file"] = {
            "path": str(report_path),
            "bytes": r_bytes,
            "sha256": r_sha,
        }

    return EXIT_COMPLETE, report


def _verify_recorded_artifact(root: Path, rec: Dict[str, Any], label: str) -> None:
    rel_posix = str(rec.get("rel_path", ""))
    expected_sha = str(rec.get("sha256", "")).lower()
    expected_bytes = rec.get("bytes")
    target = resolve_safe_rel_posix(root, rel_posix)
    if not target.is_file():
        raise CollectorError(
            "FAILED_MISSING_EXISTING_ARTIFACT",
            f"Recorded {label} missing on disk during resume: {rel_posix}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    actual_sha, actual_bytes = sha256_file_from_disk(target)
    if actual_sha != expected_sha or actual_bytes != expected_bytes:
        raise CollectorError(
            "FAILED_EXISTING_ARTIFACT_CHECKSUM_MISMATCH",
            f"Recorded {label} modified/corrupted on disk ({rel_posix}): expected=({expected_sha},{expected_bytes}), actual=({actual_sha},{actual_bytes})",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )


def _check_storage_capacity(out_root: Path, additional_bytes: int, max_total_storage_bytes: int) -> None:
    current = compute_directory_bytes(out_root)
    if current + additional_bytes > max_total_storage_bytes:
        raise CollectorError(
            "FAILED_STORAGE_BUDGET_EXCEEDED",
            f"Storage cap exceeded: current={current} + extra={additional_bytes} > max_total_storage_bytes={max_total_storage_bytes}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )


def _parse_exchange_info_onboard_dates(raw_bytes: bytes, required_symbols: Tuple[str, ...]) -> Dict[str, int]:
    try:
        payload = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollectorError(
            "FAILED_INVALID_EXCHANGE_INFO_JSON",
            f"Invalid JSON in /fapi/v1/exchangeInfo: {exc}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        ) from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("symbols"), list):
        raise CollectorError(
            "FAILED_INVALID_EXCHANGE_INFO_SCHEMA",
            "Expected object with 'symbols' array from /fapi/v1/exchangeInfo.",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    by_sym: Dict[str, int] = {}
    for entry in payload["symbols"]:
        if not isinstance(entry, dict):
            continue
        sym = entry.get("symbol")
        if sym in required_symbols:
            onboard_raw = entry.get("onboardDate")
            if onboard_raw is None:
                raise CollectorError(
                    "FAILED_MISSING_ONBOARD_DATE",
                    f"Missing onboardDate for {sym} in /fapi/v1/exchangeInfo",
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                )
            by_sym[sym] = validate_epoch_ms(onboard_raw, f"exchangeInfo.{sym}.onboardDate", "ms")

    missing_syms = [s for s in required_symbols if s not in by_sym]
    if missing_syms:
        raise CollectorError(
            "FAILED_SYMBOL_MISSING_IN_EXCHANGE_INFO",
            f"Symbol(s) {missing_syms} missing in /fapi/v1/exchangeInfo",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    return by_sym


def _validate_funding_info_json(raw_bytes: bytes) -> List[Dict[str, Any]]:
    try:
        payload = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollectorError(
            "FAILED_INVALID_FUNDING_INFO_JSON",
            f"Invalid JSON in /fapi/v1/fundingInfo: {exc}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        ) from exc
    if not isinstance(payload, list):
        raise CollectorError(
            "FAILED_INVALID_FUNDING_INFO_SCHEMA",
            "Expected JSON array from /fapi/v1/fundingInfo.",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    return [x for x in payload if isinstance(x, dict)]


def _read_refined_csv_rows(path: Path, stream: str) -> List[Dict[str, Any]]:
    raw_bytes = path.read_bytes()
    text = raw_bytes.decode("utf-8")
    reader = csv.DictReader(io.StringIO(text))
    expected_cols = list(STREAM_SCHEMAS[stream])
    if reader.fieldnames != expected_cols:
        raise CollectorError(
            "FAILED_REFINED_CSV_SCHEMA_MISMATCH",
            f"Unexpected refined CSV header in {path}: {reader.fieldnames} != {expected_cols}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    out: List[Dict[str, Any]] = []
    int_cols = {"open_time_ms", "raw_close_time_ms", "trade_count", "funding_time_ms"}
    for row in reader:
        parsed_row: Dict[str, Any] = {}
        for col in expected_cols:
            val = row[col]
            if col in int_cols:
                parsed_row[col] = int(val)
            else:
                parsed_row[col] = val
        out.append(parsed_row)
    return out


def _collect_tracked_files_for_checksums(
    out_root: Path,
    checkpoint: Dict[str, Any],
    merged_artifacts: Dict[str, Dict[str, Any]],
) -> List[str]:
    rel_paths = set()
    for meta_rec in checkpoint.get("exchange_metadata", {}).get("artifacts", {}).values():
        if isinstance(meta_rec, dict) and meta_rec.get("rel_path"):
            rel_paths.add(str(meta_rec["rel_path"]))
    for unit_rec in checkpoint.get("units", {}).values():
        for raw_rec in unit_rec.get("raw_artifacts", []):
            if isinstance(raw_rec, dict) and raw_rec.get("rel_path"):
                rel_paths.add(str(raw_rec["rel_path"]))
        ref_rec = unit_rec.get("refined_artifact")
        if isinstance(ref_rec, dict) and ref_rec.get("rel_path"):
            rel_paths.add(str(ref_rec["rel_path"]))
    for m_rec in merged_artifacts.values():
        if isinstance(m_rec, dict) and m_rec.get("rel_path"):
            rel_paths.add(str(m_rec["rel_path"]))
    if (out_root / "checkpoint.json").is_file():
        rel_paths.add("checkpoint.json")
    if (out_root / "manifest.json").is_file():
        rel_paths.add("manifest.json")
    return sorted(rel_paths)


def _write_sha256sums_from_disk(out_root: Path, rel_paths: List[str]) -> Tuple[str, int]:
    lines: List[str] = []
    for rel_posix in sorted(set(rel_paths)):
        target = resolve_safe_rel_posix(out_root, rel_posix)
        digest, _sz = sha256_file_from_disk(target)
        lines.append(f"{digest}  {rel_posix}")
    text = ("\n".join(lines) + "\n") if lines else ""
    return atomic_write_utf8_lf(out_root / "SHA256SUMS.txt", text, allow_overwrite=True)


def run_collect(
    config_path: str | Path,
    out_dir: str | Path,
    *,
    resume: bool = False,
    transport: Optional[TransportCallable] = None,
    clock_fn: Optional[Callable[[], float]] = None,
    sleep_fn: Optional[Callable[[float], None]] = None,
    utc_now_fn: Optional[Callable[[], _dt.datetime]] = None,
) -> Tuple[int, Dict[str, Any]]:
    """Execute monthly collection (or resume), verifying checksums, units, gaps, and disk hashes."""
    config = load_and_validate_config(config_path)
    out_root = validate_safe_dir_path(str(out_dir), label="out_dir")
    planned_units, meta_urls = _build_work_plan(config)
    unit_map = {u.unit_key: u for u in planned_units}

    if not resume:
        if out_root.exists():
            raise CollectorError(
                "BLOCKED_OUTPUT_DIR_EXISTS",
                f"Output directory already exists ({out_root}); use --resume to continue or specify a fresh directory.",
                EXIT_POLICY_REJECTED,
            )
        out_root.mkdir(parents=True, exist_ok=False)
        for sub in ("exchange_metadata", "raw", "refined/monthly", "refined/merged"):
            (out_root / sub).mkdir(parents=True, exist_ok=True)

        checkpoint: Dict[str, Any] = {
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "collector_version": COLLECTOR_VERSION,
            "config_scope": {
                "run_id": config.run_id,
                "symbols": list(config.symbols),
                "streams": list(config.streams),
                "start_month": config.start_month,
                "end_month": config.end_month,
                "requested_start_utc": config.requested_start_utc,
                "requested_end_exclusive_utc": config.requested_end_exclusive_utc,
                "allowed_start_utc": config.allowed_start_utc,
                "oos_forbidden_start_utc": config.oos_forbidden_start_utc,
                "fetch_exchange_metadata": config.fetch_exchange_metadata,
            },
            "config_sha256": config.config_sha256,
            "created_at_utc": _utc_now_iso(),
            "updated_at_utc": _utc_now_iso(),
            "exchange_metadata": {"artifacts": {}, "onboard_dates_ms": {}, "funding_info_adjusted_symbols": []},
            "units": {
                u.unit_key: {
                    "unit_key": u.unit_key,
                    "symbol": u.symbol,
                    "stream": u.stream,
                    "month": u.month,
                    "planned_urls": list(u.planned_urls),
                    "requested_range": {
                        "month_start_ms": u.month_start_ms,
                        "month_start_utc": format_utc_ms(u.month_start_ms),
                        "effective_end_ms": u.effective_end_ms,
                        "effective_end_utc": format_utc_ms(u.effective_end_ms),
                    },
                    "status": UNIT_PENDING,
                    "collected_at_utc": None,
                    "raw_artifacts": [],
                    "refined_artifact": None,
                    "schema": list(STREAM_SCHEMAS[u.stream]),
                    "timestamp_unit": config.expected_timestamp_unit,
                    "row_count": 0,
                    "first_ts_ms": None,
                    "first_ts_utc": None,
                    "last_ts_ms": None,
                    "last_ts_utc": None,
                    "missing_count": 0,
                    "duplicate_count": 0,
                    "identical_duplicate_count": 0,
                    "page_boundary_identical_duplicate_count": 0,
                    "intra_page_identical_duplicate_count": 0,
                    "conflicting_duplicate_count": 0,
                    "non_monotonic_count": 0,
                    "missing_settlement_mark_price_count": 0,
                    "first_populated_settlement_mark_utc": None,
                    "subsecond_offset_count": 0,
                    "non_8h_short_interval_count": 0,
                    "irregular_interval_count": 0,
                    "observed_interval_hours_min": None,
                    "observed_interval_hours_max": None,
                    "observed_interval_histogram": {},
                    "interval_warnings": [],
                    "oos_boundary_excluded_count": 0,
                    "pre_listing_excluded_count": 0,
                    "out_of_requested_window_count": 0,
                    "defects": [],
                }
                for u in planned_units
            },
            "cumulative_consumption": {
                "sessions": 0,
                "http_requests_attempted": 0,
                "http_requests_succeeded": 0,
                "retry_count": 0,
                "total_sleep_seconds": 0.0,
                "compressed_bytes_downloaded": 0,
                "uncompressed_bytes_extracted": 0,
                "elapsed_wall_seconds": 0.0,
                "last_session_status": "INITIALIZED",
            },
        }
    else:
        cp_path = out_root / "checkpoint.json"
        if not out_root.is_dir() or not cp_path.is_file():
            raise CollectorError(
                "FAILED_MISSING_CHECKPOINT_FOR_RESUME",
                f"Cannot resume without existing directory and checkpoint.json at {out_root}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        try:
            checkpoint = json.loads(cp_path.read_bytes().decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CollectorError(
                "FAILED_CORRUPT_CHECKPOINT",
                f"Corrupt checkpoint.json at {cp_path}: {exc}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            ) from exc
        if not isinstance(checkpoint, dict) or checkpoint.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
            raise CollectorError(
                "FAILED_CORRUPT_CHECKPOINT",
                f"Unsupported checkpoint schema_version in {cp_path}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        expected_scope = {
            "run_id": config.run_id,
            "symbols": list(config.symbols),
            "streams": list(config.streams),
            "start_month": config.start_month,
            "end_month": config.end_month,
            "requested_start_utc": config.requested_start_utc,
            "requested_end_exclusive_utc": config.requested_end_exclusive_utc,
            "allowed_start_utc": config.allowed_start_utc,
            "oos_forbidden_start_utc": config.oos_forbidden_start_utc,
            "fetch_exchange_metadata": config.fetch_exchange_metadata,
        }
        if checkpoint.get("config_scope") != expected_scope:
            raise CollectorError(
                "BLOCKED_RESUME_CONFIG_SCOPE_MISMATCH",
                "Config scope (symbols/streams/period/metadata flag) does not match existing checkpoint.",
                EXIT_POLICY_REJECTED,
            )
        cum_existing = checkpoint.get("cumulative_consumption")
        if not isinstance(cum_existing, dict):
            raise CollectorError(
                "FAILED_CORRUPT_CHECKPOINT",
                "Missing cumulative_consumption object in checkpoint.json.",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        for int_k in (
            "sessions",
            "http_requests_attempted",
            "http_requests_succeeded",
            "retry_count",
            "compressed_bytes_downloaded",
            "uncompressed_bytes_extracted",
        ):
            v_int = cum_existing.get(int_k)
            if isinstance(v_int, bool) or not isinstance(v_int, int) or v_int < 0:
                raise CollectorError(
                    "FAILED_CORRUPT_CHECKPOINT",
                    f"Invalid cumulative_consumption.{int_k}={v_int!r} in checkpoint.json.",
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                )
        for num_k in ("elapsed_wall_seconds",):
            v_num = cum_existing.get(num_k)
            if isinstance(v_num, bool) or not isinstance(v_num, (int, float)) or not math.isfinite(float(v_num)) or float(v_num) < 0.0:
                raise CollectorError(
                    "FAILED_CORRUPT_CHECKPOINT",
                    f"Invalid cumulative_consumption.{num_k}={v_num!r} in checkpoint.json.",
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                )
        sleep_prev = cum_existing.get("total_sleep_seconds", 0.0)
        if isinstance(sleep_prev, bool) or not isinstance(sleep_prev, (int, float)) or not math.isfinite(float(sleep_prev)) or float(sleep_prev) < 0.0:
            raise CollectorError(
                "FAILED_CORRUPT_CHECKPOINT",
                f"Invalid cumulative_consumption.total_sleep_seconds={sleep_prev!r} in checkpoint.json.",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )

        recorded_raw_bytes = 0
        # Verify integrity of ALL previously saved exchange_metadata and raw/refined files BEFORE making any new HTTP calls!
        for m_label, m_rec in checkpoint.get("exchange_metadata", {}).get("artifacts", {}).items():
            if isinstance(m_rec, dict):
                _verify_recorded_artifact(out_root, m_rec, f"exchange_metadata:{m_label}")
                recorded_raw_bytes += int(m_rec.get("bytes", 0))
        for ukey, urec in checkpoint.get("units", {}).items():
            for raw_rec in urec.get("raw_artifacts", []):
                _verify_recorded_artifact(out_root, raw_rec, f"{ukey}:raw")
                recorded_raw_bytes += int(raw_rec.get("bytes", 0))
            if isinstance(urec.get("refined_artifact"), dict):
                _verify_recorded_artifact(out_root, urec["refined_artifact"], f"{ukey}:refined")
        if int(cum_existing["compressed_bytes_downloaded"]) < recorded_raw_bytes:
            raise CollectorError(
                "FAILED_CORRUPT_CHECKPOINT",
                (
                    f"Checkpoint cumulative compressed_bytes_downloaded={cum_existing['compressed_bytes_downloaded']} "
                    f"is lower than verified raw artifacts on disk ({recorded_raw_bytes} B)."
                ),
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )

    prior_cum = checkpoint["cumulative_consumption"]
    prior_sessions = int(prior_cum["sessions"])
    tracker = BudgetTracker(
        prior_http_requests_attempted=int(prior_cum["http_requests_attempted"]),
        prior_http_requests_succeeded=int(prior_cum["http_requests_succeeded"]),
        prior_retry_count=int(prior_cum["retry_count"]),
        prior_total_sleep_seconds=float(prior_cum.get("total_sleep_seconds", 0.0)),
        prior_compressed_bytes_downloaded=int(prior_cum["compressed_bytes_downloaded"]),
        prior_uncompressed_bytes_extracted=int(prior_cum["uncompressed_bytes_extracted"]),
        prior_elapsed_wall_seconds=float(prior_cum["elapsed_wall_seconds"]),
    )

    reused_verified_units = 0
    runtime_error: Optional[CollectorError] = None
    active_unit_key: Optional[str] = None
    merged_artifacts: Dict[str, Dict[str, Any]] = {}
    cross_month_defects: List[str] = []

    def _save_checkpoint() -> None:
        checkpoint["updated_at_utc"] = _utc_now_iso()
        atomic_write_json(out_root / "checkpoint.json", checkpoint, allow_overwrite=True)

    def _sync_checkpoint_consumption(last_session_status: Optional[str] = None) -> None:
        if tracker.started_monotonic is not None and "client" in locals_ref:
            c_obj = locals_ref["client"]
            tracker.elapsed_wall_seconds = max(
                tracker.elapsed_wall_seconds,
                max(0.0, float(c_obj.clock_fn()) - tracker.started_monotonic),
            )
        cum_obj = checkpoint["cumulative_consumption"]
        cum_obj["sessions"] = prior_sessions + 1
        cum_obj["http_requests_attempted"] = tracker.total_http_requests_attempted
        cum_obj["http_requests_succeeded"] = tracker.total_http_requests_succeeded
        cum_obj["retry_count"] = tracker.total_retry_count
        cum_obj["total_sleep_seconds"] = tracker.total_sleep_seconds_cumulative
        cum_obj["compressed_bytes_downloaded"] = tracker.total_compressed_bytes_downloaded
        cum_obj["uncompressed_bytes_extracted"] = tracker.total_uncompressed_bytes_extracted
        cum_obj["elapsed_wall_seconds"] = tracker.total_elapsed_wall_seconds
        if last_session_status is not None:
            cum_obj["last_session_status"] = last_session_status
        _save_checkpoint()

    locals_ref: Dict[str, Any] = {}
    client = RateLimitedClient(
        config,
        transport=transport,
        clock_fn=clock_fn,
        sleep_fn=sleep_fn,
        utc_now_fn=utc_now_fn,
        tracker=tracker,
        on_budget_update=_sync_checkpoint_consumption,
    )
    locals_ref["client"] = client
    _sync_checkpoint_consumption("IN_PROGRESS")

    try:
        # Step 1: Exchange metadata (onboardDate & fundingInfo)
        onboard_dates_ms: Dict[str, int] = {
            k: int(v) for k, v in checkpoint.get("exchange_metadata", {}).get("onboard_dates_ms", {}).items()
        }
        if config.fetch_exchange_metadata:
            meta_artifacts = checkpoint["exchange_metadata"]["artifacts"]
            if (
                resume
                and "exchange_info" in meta_artifacts
                and "funding_info" in meta_artifacts
                and len(onboard_dates_ms) == len(config.symbols)
            ):
                pass
            else:
                ex_url = f"{config.fapi_base_url}/fapi/v1/exchangeInfo"
                fi_url = f"{config.fapi_base_url}/fapi/v1/fundingInfo"
                ex_resp = client.get(ex_url, rate_bucket="default")
                onboard_dates_ms = _parse_exchange_info_onboard_dates(ex_resp.body, config.symbols)
                fi_resp = client.get(fi_url, rate_bucket="funding")
                fi_entries = _validate_funding_info_json(fi_resp.body)

                _check_storage_capacity(out_root, len(ex_resp.body) + len(fi_resp.body), config.max_total_storage_bytes)
                ex_rel = "exchange_metadata/exchange_info.json"
                ex_sha, ex_bytes = atomic_write_bytes(out_root / ex_rel, ex_resp.body, allow_overwrite=False)
                fi_rel = "exchange_metadata/funding_info.json"
                fi_sha, fi_bytes = atomic_write_bytes(out_root / fi_rel, fi_resp.body, allow_overwrite=False)

                meta_artifacts["exchange_info"] = {
                    "rel_path": ex_rel,
                    "url": ex_url,
                    "bytes": ex_bytes,
                    "sha256": ex_sha,
                    "collected_at_utc": _utc_now_iso(),
                }
                meta_artifacts["funding_info"] = {
                    "rel_path": fi_rel,
                    "url": fi_url,
                    "bytes": fi_bytes,
                    "sha256": fi_sha,
                    "collected_at_utc": _utc_now_iso(),
                }
                checkpoint["exchange_metadata"]["onboard_dates_ms"] = onboard_dates_ms
                checkpoint["exchange_metadata"]["funding_info_adjusted_symbols"] = sorted(
                    {
                        str(e.get("symbol"))
                        for e in fi_entries
                        if e.get("symbol") in config.symbols
                    }
                )
                _save_checkpoint()

        # Step 2: Execute monthly work units
        for u in planned_units:
            urec = checkpoint["units"][u.unit_key]
            cur_status = urec["status"]
            if resume and cur_status in {
                UNIT_VERIFIED_COMPLETE,
                UNIT_SKIPPED_PRE_LISTING,
                UNIT_INCOMPLETE_MISSING_SETTLEMENT_MARK_PRICE,
                UNIT_INCOMPLETE_MISSING_STREAM_OR_GAPS,
            }:
                if cur_status in {UNIT_VERIFIED_COMPLETE, UNIT_SKIPPED_PRE_LISTING}:
                    reused_verified_units += 1
                continue

            active_unit_key = u.unit_key
            client.check_time_budget()
            onboard_ms = onboard_dates_ms.get(u.symbol)
            if onboard_ms is not None and u.month_end_ms < onboard_ms:
                urec["status"] = UNIT_SKIPPED_PRE_LISTING
                urec["collected_at_utc"] = _utc_now_iso()
                urec["defects"] = [f"pre_listing:onboardDate={format_utc_ms(onboard_ms)}"]
                _save_checkpoint()
                continue

            is_listing_month = bool(onboard_ms is not None and u.month_start_ms < onboard_ms <= u.month_end_ms)
            effective_start_ms = onboard_ms if is_listing_month and onboard_ms is not None else u.month_start_ms

            if u.stream in STREAM_TO_VISION_PATH_SPEC:
                assert u.archive_filename and u.checksum_filename and u.inner_csv_filename
                cs_url, zip_url = u.planned_urls
                cs_resp = client.get(cs_url, rate_bucket="vision", allow_404=True)
                if cs_resp.status == 404:
                    urec["status"] = UNIT_INCOMPLETE_MISSING_STREAM_OR_GAPS
                    urec["collected_at_utc"] = _utc_now_iso()
                    urec["missing_count"] = 1
                    urec["defects"] = [f"HTTP_404_CHECKSUM:{cs_url}"]
                    _save_checkpoint()
                    continue

                expected_zip_sha = parse_binance_checksum(cs_resp.body, u.archive_filename)
                zip_resp = client.get(zip_url, rate_bucket="vision", allow_404=True)
                if zip_resp.status == 404:
                    urec["status"] = UNIT_INCOMPLETE_MISSING_STREAM_OR_GAPS
                    urec["collected_at_utc"] = _utc_now_iso()
                    urec["missing_count"] = 1
                    urec["defects"] = [f"HTTP_404_ARCHIVE:{zip_url}"]
                    _save_checkpoint()
                    continue

                actual_zip_mem_sha = sha256_bytes_raw(zip_resp.body)
                if actual_zip_mem_sha != expected_zip_sha:
                    raise CollectorError(
                        "FAILED_ARCHIVE_CHECKSUM_MISMATCH",
                        f"SHA-256 mismatch for {u.archive_filename}: checksum={expected_zip_sha}, actual={actual_zip_mem_sha}",
                        EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                    )

                raw_csv_bytes = extract_verified_zip_csv(
                    zip_resp.body,
                    u.inner_csv_filename,
                    config.max_single_uncompressed_bytes,
                )
                tracker.uncompressed_bytes_extracted += len(raw_csv_bytes)
                audit = parse_kline_csv(
                    raw_csv_bytes,
                    stream=u.stream,
                    interval_ms=STREAM_TO_INTERVAL_MS[u.stream],
                    month_start_ms=u.month_start_ms,
                    month_end_ms=u.month_end_ms,
                    effective_start_ms=effective_start_ms,
                    requested_start_ms=config.requested_start_ms,
                    requested_end_exclusive_ms=config.requested_end_exclusive_ms,
                    is_listing_month=is_listing_month,
                    oos_forbidden_start_ms=config.oos_forbidden_start_ms,
                    expected_timestamp_unit=config.expected_timestamp_unit,
                    context=u.unit_key,
                )

                refined_text = serialize_rows_to_csv_lf(u.stream, audit.rows) if audit.is_clean else None
                extra_storage = len(cs_resp.body) + len(zip_resp.body) + (len(refined_text.encode("utf-8")) if refined_text else 0)
                _check_storage_capacity(out_root, extra_storage, config.max_total_storage_bytes)

                cs_rel = f"raw/{u.stream}/{u.symbol}/{u.month}/{u.checksum_filename}"
                zip_rel = f"raw/{u.stream}/{u.symbol}/{u.month}/{u.archive_filename}"
                cs_sha, cs_bytes = atomic_write_bytes(out_root / cs_rel, cs_resp.body, allow_overwrite=False)
                zip_sha, zip_bytes = atomic_write_bytes(out_root / zip_rel, zip_resp.body, allow_overwrite=False)
                if zip_sha != expected_zip_sha:
                    raise CollectorError(
                        "FAILED_POST_WRITE_CHECKSUM_MISMATCH",
                        f"Post-write disk SHA-256 mismatch on {zip_rel}: {zip_sha} != {expected_zip_sha}",
                        EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                    )

                urec["raw_artifacts"] = [
                    {"rel_path": cs_rel, "url": cs_url, "bytes": cs_bytes, "sha256": cs_sha},
                    {"rel_path": zip_rel, "url": zip_url, "bytes": zip_bytes, "sha256": zip_sha},
                ]
                urec["collected_at_utc"] = _utc_now_iso()
                urec["row_count"] = audit.usable_rows_count
                urec["missing_count"] = audit.missing_count
                urec["duplicate_count"] = audit.duplicate_count
                urec["identical_duplicate_count"] = audit.identical_duplicate_count
                urec["conflicting_duplicate_count"] = audit.conflicting_duplicate_count
                urec["non_monotonic_count"] = audit.non_monotonic_count
                urec["oos_boundary_excluded_count"] = audit.oos_boundary_excluded_count
                urec["pre_listing_excluded_count"] = audit.pre_listing_excluded_count
                urec["out_of_requested_window_count"] = audit.out_of_requested_window_count
                if audit.rows:
                    urec["first_ts_ms"] = audit.rows[0]["open_time_ms"]
                    urec["first_ts_utc"] = audit.rows[0]["open_time_utc"]
                    urec["last_ts_ms"] = audit.rows[-1]["open_time_ms"]
                    urec["last_ts_utc"] = audit.rows[-1]["open_time_utc"]

                if audit.conflicting_duplicate_count > 0:
                    _save_checkpoint()
                    raise CollectorError(
                        "FAILED_CONFLICTING_DUPLICATE_EVENT",
                        f"Conflicting duplicate kline rows detected in {u.unit_key}: {audit.duplicate_samples}",
                        EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                    )

                if audit.is_clean and refined_text is not None:
                    ref_rel = f"refined/monthly/{u.stream}/{u.symbol}/{u.symbol}_{u.stream}_{u.month}.csv"
                    ref_sha, ref_bytes = atomic_write_utf8_lf(out_root / ref_rel, refined_text, allow_overwrite=False)
                    urec["refined_artifact"] = {"rel_path": ref_rel, "bytes": ref_bytes, "sha256": ref_sha}
                    urec["status"] = UNIT_VERIFIED_COMPLETE
                    urec["defects"] = []
                else:
                    defects: List[str] = []
                    if audit.missing_count > 0:
                        defects.append(f"missing_bars={audit.missing_count};samples={audit.missing_samples}")
                    if audit.duplicate_count > 0:
                        defects.append(f"duplicate_bars={audit.duplicate_count};samples={audit.duplicate_samples}")
                    if audit.non_monotonic_count > 0:
                        defects.append(f"non_monotonic_bars={audit.non_monotonic_count}")
                    if not audit.rows:
                        defects.append("zero_usable_rows")
                    urec["status"] = UNIT_INCOMPLETE_MISSING_STREAM_OR_GAPS
                    urec["defects"] = defects
                _save_checkpoint()

            else:
                # Paginated REST /fapi/v1/fundingRate
                cur_start_ms = max(effective_start_ms, config.requested_start_ms)
                raw_pages: List[Tuple[str, bytes]] = []
                prev_page_sig: Optional[Tuple[int, ...]] = None
                truncated_by_cap = False
                while cur_start_ms <= u.effective_end_ms:
                    if len(raw_pages) >= config.max_funding_pages_per_month:
                        truncated_by_cap = True
                        break
                    query = urllib.parse.urlencode(
                        {
                            "symbol": u.symbol,
                            "startTime": cur_start_ms,
                            "endTime": u.effective_end_ms,
                            "limit": config.funding_page_limit,
                        }
                    )
                    page_url = f"{config.fapi_base_url}/fapi/v1/fundingRate?{query}"
                    resp = client.get(page_url, rate_bucket="funding", allow_404=False)
                    try:
                        page_json = json.loads(resp.body.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise CollectorError(
                            "FAILED_INVALID_REST_JSON",
                            f"Invalid JSON in funding page {page_url}: {exc}",
                            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                        ) from exc
                    if not isinstance(page_json, list):
                        raise CollectorError(
                            "FAILED_UNEXPECTED_REST_PAYLOAD_TYPE",
                            f"Expected list from {page_url}, got {type(page_json).__name__}",
                            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                        )
                    raw_pages.append((page_url, resp.body))
                    if not page_json:
                        break

                    page_ts_list: List[int] = []
                    for item_idx, item in enumerate(page_json):
                        if not isinstance(item, dict):
                            raise CollectorError(
                                "FAILED_UNEXPECTED_REST_PAYLOAD_TYPE",
                                f"Expected object element in {page_url} row {item_idx}",
                                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                            )
                        ft = validate_epoch_ms(
                            item.get("fundingTime"),
                            f"{u.unit_key}:page{len(raw_pages)}[{item_idx}].fundingTime",
                            config.expected_timestamp_unit,
                        )
                        page_ts_list.append(ft)

                    sig = tuple(page_ts_list)
                    if prev_page_sig is not None and sig == prev_page_sig:
                        raise CollectorError(
                            "FAILED_REPEATED_PAGINATION_PAGE",
                            f"Repeated identical funding page detected for {u.unit_key}",
                            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                        )
                    prev_page_sig = sig

                    if len(page_json) < config.funding_page_limit:
                        break
                    next_start = page_ts_list[-1] + 1
                    if next_start <= cur_start_ms:
                        raise CollectorError(
                            "FAILED_PAGINATION_STALLED",
                            f"Pagination cursor did not advance for {u.unit_key}: next={next_start} <= cur={cur_start_ms}",
                            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                        )
                    cur_start_ms = next_start

                faudit = parse_funding_pages(
                    [b for _, b in raw_pages],
                    symbol=u.symbol,
                    month_start_ms=u.month_start_ms,
                    month_end_ms=u.effective_end_ms,
                    effective_start_ms=effective_start_ms,
                    requested_start_ms=config.requested_start_ms,
                    requested_end_exclusive_ms=config.requested_end_exclusive_ms,
                    is_listing_month=is_listing_month,
                    oos_forbidden_start_ms=config.oos_forbidden_start_ms,
                    anomalous_funding_interval_warning_hours=config.anomalous_funding_interval_warning_hours,
                    expected_timestamp_unit=config.expected_timestamp_unit,
                    truncated_by_page_cap=truncated_by_cap,
                    context=u.unit_key,
                )

                refined_text = serialize_rows_to_csv_lf(u.stream, faudit.events) if faudit.is_clean else None
                extra_storage = sum(len(b) for _, b in raw_pages) + (len(refined_text.encode("utf-8")) if refined_text else 0)
                _check_storage_capacity(out_root, extra_storage, config.max_total_storage_bytes)

                raw_records: List[Dict[str, Any]] = []
                for idx, (p_url, p_bytes) in enumerate(raw_pages, start=1):
                    p_rel = f"raw/{u.stream}/{u.symbol}/{u.month}/page_{idx:03d}.json"
                    p_sha, p_disk_bytes = atomic_write_bytes(out_root / p_rel, p_bytes, allow_overwrite=False)
                    raw_records.append({"rel_path": p_rel, "url": p_url, "bytes": p_disk_bytes, "sha256": p_sha})

                urec["raw_artifacts"] = raw_records
                urec["planned_urls"] = [p_url for p_url, _ in raw_pages] or list(u.planned_urls)
                urec["collected_at_utc"] = _utc_now_iso()
                urec["row_count"] = faudit.usable_events_count
                urec["missing_count"] = faudit.missing_gap_count
                urec["duplicate_count"] = faudit.duplicate_count
                urec["identical_duplicate_count"] = (
                    faudit.page_boundary_identical_duplicate_count + faudit.intra_page_identical_duplicate_count
                )
                urec["page_boundary_identical_duplicate_count"] = faudit.page_boundary_identical_duplicate_count
                urec["intra_page_identical_duplicate_count"] = faudit.intra_page_identical_duplicate_count
                urec["conflicting_duplicate_count"] = faudit.conflicting_duplicate_count
                urec["non_monotonic_count"] = faudit.non_monotonic_count
                urec["missing_settlement_mark_price_count"] = faudit.missing_settlement_mark_price_count
                urec["first_populated_settlement_mark_utc"] = faudit.first_populated_settlement_mark_utc
                urec["subsecond_offset_count"] = faudit.subsecond_offset_count
                urec["non_8h_short_interval_count"] = faudit.non_8h_short_interval_count
                urec["irregular_interval_count"] = faudit.irregular_interval_count
                urec["observed_interval_hours_min"] = faudit.observed_interval_hours_min
                urec["observed_interval_hours_max"] = faudit.observed_interval_hours_max
                urec["observed_interval_histogram"] = faudit.observed_interval_histogram
                urec["interval_warnings"] = faudit.interval_warnings
                urec["pre_listing_excluded_count"] = faudit.pre_listing_excluded_count
                urec["out_of_requested_window_count"] = faudit.out_of_requested_window_count
                if faudit.events:
                    urec["first_ts_ms"] = faudit.events[0]["funding_time_ms"]
                    urec["first_ts_utc"] = faudit.events[0]["funding_time_utc"]
                    urec["last_ts_ms"] = faudit.events[-1]["funding_time_ms"]
                    urec["last_ts_utc"] = faudit.events[-1]["funding_time_utc"]

                if faudit.has_conflicting_duplicate:
                    _save_checkpoint()
                    raise CollectorError(
                        "FAILED_CONFLICTING_DUPLICATE_EVENT",
                        f"Conflicting funding duplicate events in {u.unit_key}: {faudit.conflicting_duplicate_samples}",
                        EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                    )

                if faudit.has_missing_settlement_mark_price:
                    urec["status"] = UNIT_INCOMPLETE_MISSING_SETTLEMENT_MARK_PRICE
                    defects = [
                        f"missing_settlement_mark_price_count={faudit.missing_settlement_mark_price_count};samples={faudit.missing_settlement_mark_price_samples}"
                    ]
                    if faudit.missing_gap_count > 0:
                        defects.append(f"funding_gaps={faudit.missing_gap_count};samples={faudit.missing_gap_samples}")
                    if faudit.non_monotonic_count > 0:
                        defects.append(f"non_monotonic_events={faudit.non_monotonic_count}")
                    urec["defects"] = defects
                elif not faudit.is_clean or refined_text is None:
                    urec["status"] = UNIT_INCOMPLETE_MISSING_STREAM_OR_GAPS
                    defects = []
                    if faudit.missing_gap_count > 0:
                        defects.append(f"funding_gaps={faudit.missing_gap_count};samples={faudit.missing_gap_samples}")
                    if faudit.non_monotonic_count > 0:
                        defects.append(f"non_monotonic_events={faudit.non_monotonic_count}")
                    if faudit.truncated_by_page_cap:
                        defects.append("truncated_by_max_funding_pages_per_month")
                    urec["defects"] = defects
                else:
                    ref_rel = f"refined/monthly/{u.stream}/{u.symbol}/{u.symbol}_{u.stream}_{u.month}.csv"
                    ref_sha, ref_bytes = atomic_write_utf8_lf(out_root / ref_rel, refined_text, allow_overwrite=False)
                    urec["refined_artifact"] = {"rel_path": ref_rel, "bytes": ref_bytes, "sha256": ref_sha}
                    urec["status"] = UNIT_VERIFIED_COMPLETE
                    urec["defects"] = []
                _save_checkpoint()

        active_unit_key = None

        # Step 3: Cross-month continuity verification and merged refined outputs
        warn_gap_ms = int(round(config.anomalous_funding_interval_warning_hours * 3_600_000))
        for symbol in config.symbols:
            for stream in config.streams:
                active_units = [
                    checkpoint["units"][_unit_key(symbol, stream, m)]
                    for m in config.months
                    if checkpoint["units"][_unit_key(symbol, stream, m)]["status"] != UNIT_SKIPPED_PRE_LISTING
                ]
                if not active_units:
                    continue
                if any(urec["status"] != UNIT_VERIFIED_COMPLETE for urec in active_units):
                    continue

                merged_rows: List[Dict[str, Any]] = []
                stitch_ok = True
                for urec in active_units:
                    ref_info = urec.get("refined_artifact")
                    if not isinstance(ref_info, dict):
                        stitch_ok = False
                        break
                    ref_path = resolve_safe_rel_posix(out_root, str(ref_info["rel_path"]))
                    month_rows = _read_refined_csv_rows(ref_path, stream)
                    if not month_rows:
                        stitch_ok = False
                        break
                    if merged_rows:
                        if stream in STREAM_TO_INTERVAL_MS:
                            interval_ms = STREAM_TO_INTERVAL_MS[stream]
                            prev_open = merged_rows[-1]["open_time_ms"]
                            cur_open = month_rows[0]["open_time_ms"]
                            if cur_open <= prev_open:
                                stitch_ok = False
                                urec["status"] = UNIT_INCOMPLETE_MISSING_STREAM_OR_GAPS
                                urec["duplicate_count"] += 1
                                urec["defects"].append(f"cross_month_duplicate:{format_utc_ms(cur_open)}<={format_utc_ms(prev_open)}")
                                cross_month_defects.append(f"{symbol}/{stream}/{urec['month']}:duplicate_boundary")
                                break
                            if cur_open != prev_open + interval_ms:
                                gap_bars = ((cur_open - prev_open) // interval_ms) - 1
                                stitch_ok = False
                                urec["status"] = UNIT_INCOMPLETE_MISSING_STREAM_OR_GAPS
                                urec["missing_count"] += gap_bars
                                urec["defects"].append(f"cross_month_gap:{format_utc_ms(prev_open)}->{format_utc_ms(cur_open)}({gap_bars})")
                                cross_month_defects.append(f"{symbol}/{stream}/{urec['month']}:gap_boundary({gap_bars})")
                                break
                        else:
                            prev_row = merged_rows[-1]
                            cur_row = month_rows[0]
                            prev_ft = prev_row["funding_time_ms"]
                            cur_ft = cur_row["funding_time_ms"]
                            if cur_ft == prev_ft:
                                prev_fp = (prev_row["funding_rate"], prev_row["settlement_mark_price"], prev_row["rate_type"])
                                cur_fp = (cur_row["funding_rate"], cur_row["settlement_mark_price"], cur_row["rate_type"])
                                urec["duplicate_count"] += 1
                                if prev_fp == cur_fp:
                                    urec["identical_duplicate_count"] += 1
                                    urec["page_boundary_identical_duplicate_count"] += 1
                                    month_rows = month_rows[1:]
                                    if not month_rows:
                                        continue
                                    cur_row = month_rows[0]
                                    cur_ft = cur_row["funding_time_ms"]
                                else:
                                    stitch_ok = False
                                    urec["conflicting_duplicate_count"] += 1
                                    urec["status"] = UNIT_FAILED_CORRUPT_OR_CHECKSUM
                                    urec["defects"].append(
                                        f"cross_month_funding_conflict:{format_utc_ms(cur_ft)}:{prev_fp} vs {cur_fp}"
                                    )
                                    cross_month_defects.append(f"{symbol}/{stream}/{urec['month']}:funding_conflict_boundary")
                                    _save_checkpoint()
                                    raise CollectorError(
                                        "FAILED_CONFLICTING_DUPLICATE_EVENT",
                                        f"Conflicting cross-month funding duplicate at {format_utc_ms(cur_ft)} for {symbol}/{urec['month']}",
                                        EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                                    )
                            elif cur_ft < prev_ft:
                                stitch_ok = False
                                urec["status"] = UNIT_INCOMPLETE_MISSING_STREAM_OR_GAPS
                                urec["non_monotonic_count"] += 1
                                urec["defects"].append(f"cross_month_funding_non_monotonic:{format_utc_ms(cur_ft)}<{format_utc_ms(prev_ft)}")
                                cross_month_defects.append(f"{symbol}/{stream}/{urec['month']}:funding_non_monotonic_boundary")
                                break
                            delta_ms = cur_ft - prev_ft
                            obs_h = round(delta_ms / 3_600_000.0, 6)
                            month_rows[0]["observed_interval_hours"] = f"{obs_h:g}"
                            if not (int(7.95 * 3_600_000) <= delta_ms <= int(8.05 * 3_600_000)):
                                urec["irregular_interval_count"] = int(urec.get("irregular_interval_count", 0)) + 1
                            if delta_ms < int(7.95 * 3_600_000):
                                urec["non_8h_short_interval_count"] = int(urec.get("non_8h_short_interval_count", 0)) + 1
                            if delta_ms > warn_gap_ms:
                                warns = list(urec.get("interval_warnings", []))
                                warns.append(f"cross_month_long_interval:{format_utc_ms(prev_ft)}->{format_utc_ms(cur_ft)}({obs_h}h)")
                                urec["interval_warnings"] = warns[:10]
                    merged_rows.extend(month_rows)

                if not stitch_ok:
                    _save_checkpoint()
                    continue

                merged_text = serialize_rows_to_csv_lf(stream, merged_rows)
                _check_storage_capacity(out_root, len(merged_text.encode("utf-8")), config.max_total_storage_bytes)
                m_rel = f"refined/merged/{symbol}_{stream}.csv"
                m_sha, m_bytes = atomic_write_utf8_lf(out_root / m_rel, merged_text, allow_overwrite=True)
                merged_artifacts[f"{symbol}|{stream}"] = {
                    "rel_path": m_rel,
                    "bytes": m_bytes,
                    "sha256": m_sha,
                    "row_count": len(merged_rows),
                    "first_ts_utc": merged_rows[0]["open_time_utc"] if stream in STREAM_TO_INTERVAL_MS else merged_rows[0]["funding_time_utc"],
                    "last_ts_utc": merged_rows[-1]["open_time_utc"] if stream in STREAM_TO_INTERVAL_MS else merged_rows[-1]["funding_time_utc"],
                }

    except CollectorError as exc:
        runtime_error = exc
        if active_unit_key and active_unit_key in checkpoint["units"]:
            urec = checkpoint["units"][active_unit_key]
            if exc.code in {
                "FAILED_HTTP_BUDGET_EXHAUSTED",
                "FAILED_DOWNLOAD_BYTE_BUDGET_EXHAUSTED",
                "FAILED_RESPONSE_BYTE_LIMIT_EXCEEDED",
                "FAILED_STORAGE_BUDGET_EXCEEDED",
                "FAILED_TIME_BUDGET_EXCEEDED",
                "FAILED_RETRY_AFTER_EXCEEDS_REMAINING_TIME",
            }:
                urec["status"] = UNIT_FAILED_BUDGET_EXCEEDED
            elif exc.code.startswith("BLOCKED_"):
                urec["status"] = UNIT_FAILED_POLICY_VIOLATION
            elif exc.code in {
                "FAILED_RATE_LIMIT_EXHAUSTED",
                "FAILED_IP_BAN_418",
                "FAILED_RETRY_AFTER_EXCEEDS_MAX_WAIT",
                "FAILED_INVALID_RETRY_AFTER",
                "FAILED_EXCHANGE_WEIGHT_LIMIT_REACHED",
                "FAILED_EXCHANGE_WEIGHT_LIMIT_NOT_RECOVERED",
                "FAILED_SERVER_ERROR_EXHAUSTED",
                "FAILED_NETWORK_RETRIES_EXHAUSTED",
                "FAILED_HTTP_TRANSPORT",
                "FAILED_HTTP_CLIENT_ERROR",
            }:
                urec["status"] = UNIT_FAILED_TRANSPORT_OR_RATE_LIMIT
            else:
                urec["status"] = UNIT_FAILED_CORRUPT_OR_CHECKSUM
            urec["defects"] = list(urec.get("defects", [])) + [f"{exc.code}: {exc.message}"]
            _save_checkpoint()
    finally:
        aborted_abnormally = sys.exc_info()[0] is not None and runtime_error is None
        _sync_checkpoint_consumption(
            "ABORTED_ABNORMALLY" if aborted_abnormally else ("FAILED" if runtime_error is not None else "FINALIZING")
        )

    # Build stream-level summaries and determine final verdict/exit code
    unit_records = [checkpoint["units"][u.unit_key] for u in planned_units]
    failed_units = [u for u in unit_records if u["status"] in TERMINAL_FAILED_STATUSES]
    incomplete_units = [u for u in unit_records if u["status"] in TERMINAL_INCOMPLETE_STATUSES]
    pending_units = [u for u in unit_records if u["status"] == UNIT_PENDING]
    verified_units = [u for u in unit_records if u["status"] == UNIT_VERIFIED_COMPLETE]
    skipped_pre_listing_units = [u for u in unit_records if u["status"] == UNIT_SKIPPED_PRE_LISTING]

    if runtime_error is not None or failed_units:
        overall_status = "FAILED"
        overall_exit = runtime_error.exit_code if runtime_error is not None else EXIT_RUNTIME_OR_INTEGRITY_ERROR
    elif incomplete_units or pending_units or cross_month_defects:
        overall_status = "INCOMPLETE"
        overall_exit = EXIT_INCOMPLETE_DATA
    elif not verified_units and len(skipped_pre_listing_units) == len(unit_records):
        overall_status = "INCOMPLETE"
        overall_exit = EXIT_INCOMPLETE_DATA
    else:
        overall_status = "COMPLETE"
        overall_exit = EXIT_COMPLETE

    _sync_checkpoint_consumption(overall_status)

    stream_summaries: Dict[str, Any] = {}
    for symbol in config.symbols:
        sym_summary: Dict[str, Any] = {
            "onboard_date_ms": checkpoint["exchange_metadata"]["onboard_dates_ms"].get(symbol),
            "onboard_date_utc": (
                format_utc_ms(int(checkpoint["exchange_metadata"]["onboard_dates_ms"][symbol]))
                if symbol in checkpoint["exchange_metadata"]["onboard_dates_ms"]
                else None
            ),
            "streams": {},
        }
        for stream in config.streams:
            s_units = [checkpoint["units"][_unit_key(symbol, stream, m)] for m in config.months]
            non_skipped = [u for u in s_units if u["status"] != UNIT_SKIPPED_PRE_LISTING]
            ver_non_skipped = [u for u in non_skipped if u["status"] == UNIT_VERIFIED_COMPLETE]
            if not non_skipped:
                s_status = UNIT_SKIPPED_PRE_LISTING
            elif len(ver_non_skipped) == len(non_skipped) and f"{symbol}|{stream}" in merged_artifacts:
                s_status = UNIT_VERIFIED_COMPLETE
            elif any(u["status"] == UNIT_INCOMPLETE_MISSING_SETTLEMENT_MARK_PRICE for u in non_skipped):
                s_status = UNIT_INCOMPLETE_MISSING_SETTLEMENT_MARK_PRICE
            elif any(u["status"] in TERMINAL_FAILED_STATUSES for u in non_skipped):
                s_status = "FAILED"
            else:
                s_status = UNIT_INCOMPLETE_MISSING_STREAM_OR_GAPS

            first_ts_ms_vals = [u["first_ts_ms"] for u in ver_non_skipped if u["first_ts_ms"] is not None]
            last_ts_ms_vals = [u["last_ts_ms"] for u in ver_non_skipped if u["last_ts_ms"] is not None]
            first_pop_mp_vals = [
                u["first_populated_settlement_mark_utc"]
                for u in s_units
                if u.get("first_populated_settlement_mark_utc") is not None
            ]
            sym_summary["streams"][stream] = {
                "status": s_status,
                "schema_columns": list(STREAM_SCHEMAS[stream]),
                "timestamp_unit": config.expected_timestamp_unit,
                "first_available_utc": format_utc_ms(min(first_ts_ms_vals)) if first_ts_ms_vals else None,
                "last_available_utc": format_utc_ms(max(last_ts_ms_vals)) if last_ts_ms_vals else None,
                "first_populated_settlement_mark_utc": min(first_pop_mp_vals) if first_pop_mp_vals else None,
                "total_rows": sum(int(u["row_count"]) for u in ver_non_skipped),
                "verified_months_count": len(ver_non_skipped),
                "skipped_pre_listing_months_count": sum(1 for u in s_units if u["status"] == UNIT_SKIPPED_PRE_LISTING),
                "missing_count": sum(int(u["missing_count"]) for u in s_units),
                "duplicate_count": sum(int(u["duplicate_count"]) for u in s_units),
                "identical_duplicate_count": sum(int(u.get("identical_duplicate_count", 0)) for u in s_units),
                "page_boundary_identical_duplicate_count": sum(int(u.get("page_boundary_identical_duplicate_count", 0)) for u in s_units),
                "intra_page_identical_duplicate_count": sum(int(u.get("intra_page_identical_duplicate_count", 0)) for u in s_units),
                "conflicting_duplicate_count": sum(int(u.get("conflicting_duplicate_count", 0)) for u in s_units),
                "non_monotonic_count": sum(int(u["non_monotonic_count"]) for u in s_units),
                "missing_settlement_mark_price_count": sum(int(u["missing_settlement_mark_price_count"]) for u in s_units),
                "subsecond_offset_count": sum(int(u["subsecond_offset_count"]) for u in s_units),
                "non_8h_short_interval_count": sum(int(u["non_8h_short_interval_count"]) for u in s_units),
                "irregular_interval_count": sum(int(u.get("irregular_interval_count", 0)) for u in s_units),
                "interval_warnings_count": sum(len(u.get("interval_warnings", [])) for u in s_units),
                "oos_boundary_excluded_count": sum(int(u["oos_boundary_excluded_count"]) for u in s_units),
                "pre_listing_excluded_count": sum(int(u.get("pre_listing_excluded_count", 0)) for u in s_units),
                "out_of_requested_window_count": sum(int(u.get("out_of_requested_window_count", 0)) for u in s_units),
                "merged_artifact": merged_artifacts.get(f"{symbol}|{stream}"),
            }
        stream_summaries[symbol] = sym_summary

    total_disk_bytes = compute_directory_bytes(out_root)
    manifest: Dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "collector_version": COLLECTOR_VERSION,
        "run_id": config.run_id,
        "mode_label": config.mode_label,
        "resume": resume,
        "collected_at_utc": _utc_now_iso(),
        "status": overall_status,
        "exit_code": overall_exit,
        "error": (
            {"code": runtime_error.code, "message": runtime_error.message}
            if runtime_error is not None
            else None
        ),
        "config_snapshot": {
            "config_sha256": config.config_sha256,
            "symbols": list(config.symbols),
            "streams": list(config.streams),
            "start_month": config.start_month,
            "end_month": config.end_month,
            "requested_start_utc": config.requested_start_utc,
            "requested_end_exclusive_utc": config.requested_end_exclusive_utc,
            "allowed_start_utc": config.allowed_start_utc,
            "oos_forbidden_start_utc": config.oos_forbidden_start_utc,
            "allowed_hosts": list(config.allowed_hosts),
            "budgets": {
                "max_http_requests": config.max_http_requests,
                "max_compressed_download_bytes": config.max_compressed_download_bytes,
                "max_single_response_bytes": config.max_single_response_bytes,
                "max_single_uncompressed_bytes": config.max_single_uncompressed_bytes,
                "max_total_storage_bytes": config.max_total_storage_bytes,
                "max_wall_time_seconds": config.max_wall_time_seconds,
                "budget_rationale": config.budget_rationale,
            },
            "governance": {
                "production_blocked": True,
                "public_market_data_only": True,
                "allow_credentials": False,
                "allow_order_endpoints": False,
                "allow_paid_services": False,
            },
        },
        "source_attribution": OFFICIAL_SOURCES_METADATA,
        "exchange_metadata": checkpoint["exchange_metadata"],
        "budget_consumption": {
            "this_session": {
                "http_requests_attempted": tracker.http_requests_attempted,
                "http_requests_succeeded": tracker.http_requests_succeeded,
                "retry_count": tracker.retry_count,
                "total_sleep_seconds": round(tracker.total_sleep_seconds, 6),
                "elapsed_wall_seconds": round(tracker.elapsed_wall_seconds, 6),
                "compressed_bytes_downloaded": tracker.compressed_bytes_downloaded,
                "uncompressed_bytes_extracted": tracker.uncompressed_bytes_extracted,
                "max_observed_used_weight_1m": tracker.max_observed_used_weight_1m,
                "last_observed_used_weight_1m": tracker.last_observed_used_weight_1m,
                "weight_limit_cooldown_events": tracker.weight_limit_cooldown_events,
                "status_code_counts": tracker.status_code_counts,
                "reused_verified_units": reused_verified_units,
            },
            "cumulative": {
                **checkpoint["cumulative_consumption"],
                "remaining_http_requests": max(0, config.max_http_requests - tracker.total_http_requests_attempted),
                "remaining_compressed_download_bytes": max(
                    0, config.max_compressed_download_bytes - tracker.total_compressed_bytes_downloaded
                ),
            },
            "total_disk_bytes_on_disk": total_disk_bytes,
        },
        "unit_status_counts": {
            "total": len(unit_records),
            "verified_complete": len(verified_units),
            "skipped_pre_listing": len(skipped_pre_listing_units),
            "incomplete": len(incomplete_units),
            "failed": len(failed_units),
            "pending": len(pending_units),
        },
        "cross_month_defects": cross_month_defects,
        "stream_summaries": stream_summaries,
        "merged_artifacts": merged_artifacts,
        "units": unit_records,
        "checksums_file": "SHA256SUMS.txt",
    }

    manifest_path = out_root / "manifest.json"
    atomic_write_json(manifest_path, manifest, allow_overwrite=True)

    tracked_rels = _collect_tracked_files_for_checksums(out_root, checkpoint, merged_artifacts)
    sums_sha, sums_bytes = _write_sha256sums_from_disk(out_root, tracked_rels)

    summary_out = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "status": overall_status,
        "exit_code": overall_exit,
        "out_dir": str(out_root),
        "unit_status_counts": manifest["unit_status_counts"],
        "budget_consumption": manifest["budget_consumption"],
        "error": manifest["error"],
        "sha256sums_file": {"rel_path": "SHA256SUMS.txt", "bytes": sums_bytes, "sha256": sums_sha},
    }
    return overall_exit, summary_out


def run_verify(package_dir: str | Path, *, require_complete: bool = False) -> Tuple[int, Dict[str, Any]]:
    """Verify disk-byte SHA-256 checksums, POSIX paths, OOS bounds, and manifest integrity offline."""
    root = validate_safe_dir_path(str(package_dir), label="package_dir")
    if not root.is_dir():
        raise CollectorError(
            "FAILED_MISSING_PACKAGE_DIR",
            f"Package directory does not exist: {root}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    sums_path = root / "SHA256SUMS.txt"
    manifest_path = root / "manifest.json"
    if not sums_path.is_file():
        raise CollectorError("FAILED_MISSING_SHA256SUMS", f"Missing SHA256SUMS.txt in {root}", EXIT_RUNTIME_OR_INTEGRITY_ERROR)
    if not manifest_path.is_file():
        raise CollectorError("FAILED_MISSING_MANIFEST", f"Missing manifest.json in {root}", EXIT_RUNTIME_OR_INTEGRITY_ERROR)

    sums_bytes = sums_path.read_bytes()
    if b"\r" in sums_bytes:
        raise CollectorError(
            "FAILED_CHECKSUMS_CRLF_DETECTED",
            "SHA256SUMS.txt must use LF line endings only.",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    try:
        sums_text = sums_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CollectorError("FAILED_MALFORMED_SHA256SUMS", f"SHA256SUMS.txt is not UTF-8: {exc}", EXIT_RUNTIME_OR_INTEGRITY_ERROR) from exc

    verified_hashes: Dict[str, str] = {}
    verified_bytes: Dict[str, int] = {}
    for line_no, line in enumerate(sums_text.splitlines(), start=1):
        if not line.strip():
            continue
        parts = line.split("  ", 1)
        if len(parts) != 2:
            raise CollectorError(
                "FAILED_MALFORMED_SHA256SUMS",
                f"Malformed line {line_no} in SHA256SUMS.txt: {line!r}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        expected_hex, rel_posix = parts
        if not HEX64_RE.match(expected_hex):
            raise CollectorError(
                "FAILED_MALFORMED_SHA256SUMS",
                f"Invalid SHA-256 hex on line {line_no} in SHA256SUMS.txt: {expected_hex!r}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        target = resolve_safe_rel_posix(root, rel_posix)
        actual_hex, actual_sz = sha256_file_from_disk(target)
        if actual_hex != expected_hex.lower():
            raise CollectorError(
                "FAILED_CHECKSUM_VERIFICATION",
                f"Disk-byte SHA-256 mismatch for {rel_posix}: expected={expected_hex.lower()}, actual={actual_hex}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        verified_hashes[rel_posix] = actual_hex
        verified_bytes[rel_posix] = actual_sz

    if "manifest.json" not in verified_hashes:
        raise CollectorError(
            "FAILED_MANIFEST_NOT_IN_SHA256SUMS",
            "manifest.json is missing from SHA256SUMS.txt",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )

    try:
        manifest = json.loads(manifest_path.read_bytes().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollectorError("FAILED_CORRUPT_MANIFEST", f"Invalid manifest.json: {exc}", EXIT_RUNTIME_OR_INTEGRITY_ERROR) from exc

    if not isinstance(manifest, dict) or manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise CollectorError("FAILED_CORRUPT_MANIFEST", "Unsupported manifest.json schema_version", EXIT_RUNTIME_OR_INTEGRITY_ERROR)

    cfg_snap = manifest.get("config_snapshot", {})
    oos_str = str(cfg_snap.get("oos_forbidden_start_utc", ""))
    if not oos_str or oos_str > HARD_OOS_FORBIDDEN_START_UTC:
        raise CollectorError(
            "FAILED_OOS_POLICY_IN_MANIFEST",
            f"Manifest oos_forbidden_start_utc={oos_str!r} violates ceiling {HARD_OOS_FORBIDDEN_START_UTC!r}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    oos_ms = parse_iso_utc_to_ms(oos_str)
    if oos_ms > HARD_OOS_FORBIDDEN_START_MS:
        raise CollectorError(
            "FAILED_OOS_POLICY_IN_MANIFEST",
            f"Manifest oos_forbidden_start_ms={oos_ms} violates ceiling {HARD_OOS_FORBIDDEN_START_MS}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    req_end_str = cfg_snap.get("requested_end_exclusive_utc")
    if req_end_str is not None:
        req_end_ms = parse_iso_utc_to_ms(str(req_end_str))
        if req_end_ms >= oos_ms or req_end_ms >= HARD_OOS_FORBIDDEN_START_MS:
            raise CollectorError(
                "FAILED_OOS_POLICY_IN_MANIFEST",
                f"Manifest requested_end_exclusive_utc={req_end_str!r} touches/crosses OOS boundary",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
    end_month_str = str(cfg_snap.get("end_month", ""))
    if end_month_str:
        _, _, last_next_ms = month_bounds_ms(end_month_str)
        if last_next_ms >= oos_ms or last_next_ms >= HARD_OOS_FORBIDDEN_START_MS:
            raise CollectorError(
                "FAILED_OOS_POLICY_IN_MANIFEST",
                f"Manifest end_month={end_month_str!r} full-archive upper bound touches/crosses OOS boundary",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )

    # Ensure every file referenced inside manifest.json is covered and matches SHA256SUMS.txt
    referenced_recs: List[Dict[str, Any]] = []
    for meta_rec in manifest.get("exchange_metadata", {}).get("artifacts", {}).values():
        if isinstance(meta_rec, dict):
            referenced_recs.append(meta_rec)
    for unit_rec in manifest.get("units", []):
        for raw_rec in unit_rec.get("raw_artifacts", []):
            if isinstance(raw_rec, dict):
                referenced_recs.append(raw_rec)
        if isinstance(unit_rec.get("refined_artifact"), dict):
            referenced_recs.append(unit_rec["refined_artifact"])
    for m_rec in manifest.get("merged_artifacts", {}).values():
        if isinstance(m_rec, dict):
            referenced_recs.append(m_rec)

    for rec in referenced_recs:
        rel_p = str(rec.get("rel_path", ""))
        exp_sha = str(rec.get("sha256", "")).lower()
        exp_sz = rec.get("bytes")
        if rel_p not in verified_hashes:
            raise CollectorError(
                "FAILED_REFERENCED_FILE_NOT_IN_SHA256SUMS",
                f"Manifest artifact {rel_p} missing from SHA256SUMS.txt",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        if verified_hashes[rel_p] != exp_sha or verified_bytes[rel_p] != exp_sz:
            raise CollectorError(
                "FAILED_MANIFEST_CHECKSUM_DRIFT",
                f"Manifest metadata disagrees with disk hash/size for {rel_p}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )

    manifest_status = str(manifest.get("status", ""))
    manifest_exit = int(manifest.get("exit_code", EXIT_RUNTIME_OR_INTEGRITY_ERROR))
    if require_complete and (manifest_status != "COMPLETE" or manifest_exit != EXIT_COMPLETE):
        out_exit = EXIT_INCOMPLETE_DATA if manifest_status == "INCOMPLETE" else EXIT_RUNTIME_OR_INTEGRITY_ERROR
        return out_exit, {
            "status": "VERIFY_INCOMPLETE",
            "exit_code": out_exit,
            "manifest_status": manifest_status,
            "manifest_exit_code": manifest_exit,
            "files_verified_count": len(verified_hashes),
        }

    return EXIT_COMPLETE, {
        "status": "VERIFY_PASS",
        "exit_code": EXIT_COMPLETE,
        "manifest_status": manifest_status,
        "manifest_exit_code": manifest_exit,
        "files_verified_count": len(verified_hashes),
        "manifest_sha256": verified_hashes["manifest.json"],
    }


def run_export_bundle(
    package_dir: str | Path,
    archive_path: str | Path,
    *,
    require_complete: bool = True,
) -> Tuple[int, Dict[str, Any]]:
    """Verify package integrity offline and write a deterministic .tar.gz + .sha256 bundle."""
    v_code, v_res = run_verify(package_dir, require_complete=require_complete)
    if v_code != EXIT_COMPLETE:
        return v_code, {"status": "EXPORT_BLOCKED_BY_VERIFY", "exit_code": v_code, "verify": v_res}

    root = validate_safe_dir_path(str(package_dir), label="package_dir")
    out_tar = validate_safe_dir_path(str(archive_path), label="archive_path")
    if out_tar.exists():
        raise CollectorError(
            "BLOCKED_ARCHIVE_ALREADY_EXISTS",
            f"Refusing to overwrite existing archive: {out_tar}",
            EXIT_POLICY_REJECTED,
        )
    out_tar.parent.mkdir(parents=True, exist_ok=True)

    sums_lines = (root / "SHA256SUMS.txt").read_bytes().decode("utf-8").splitlines()
    rel_files = sorted({line.split("  ", 1)[1] for line in sums_lines if line.strip()} | {"SHA256SUMS.txt"})

    tmp_tar = out_tar.parent / f".tmp.{out_tar.name}.{os.getpid()}"
    try:
        with tmp_tar.open("wb") as raw_fp:
            with tarfile.open(fileobj=raw_fp, mode="w:gz", compresslevel=6) as tf:
                for rel_posix in rel_files:
                    src = resolve_safe_rel_posix(root, rel_posix)
                    data = src.read_bytes()
                    tinfo = tarfile.TarInfo(name=rel_posix)
                    tinfo.size = len(data)
                    tinfo.mode = 0o644
                    tinfo.mtime = 0
                    tinfo.uid = 0
                    tinfo.gid = 0
                    tinfo.uname = "root"
                    tinfo.gname = "root"
                    tf.addfile(tinfo, io.BytesIO(data))
            raw_fp.flush()
            os.fsync(raw_fp.fileno())
        os.replace(tmp_tar, out_tar)
    except Exception:
        if tmp_tar.exists():
            try:
                tmp_tar.unlink()
            except OSError:
                pass
        raise

    tar_sha, tar_bytes = sha256_file_from_disk(out_tar)
    sidecar_path = Path(f"{out_tar}.sha256")
    sidecar_sha, sidecar_bytes = atomic_write_utf8_lf(
        sidecar_path,
        f"{tar_sha}  {out_tar.name}\n",
        allow_overwrite=False,
    )
    return EXIT_COMPLETE, {
        "status": "EXPORT_PASS",
        "exit_code": EXIT_COMPLETE,
        "archive_path": str(out_tar),
        "archive_bytes": tar_bytes,
        "archive_sha256": tar_sha,
        "sidecar_sha256_path": str(sidecar_path),
        "sidecar_bytes": sidecar_bytes,
        "sidecar_sha256": sidecar_sha,
        "bundled_files_count": len(rel_files),
    }
