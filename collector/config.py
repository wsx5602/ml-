"""Strict configuration schema and pre-transport governance policy validation."""

from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Tuple

from .constants import (
    CONFIG_SCHEMA_VERSION,
    EXIT_POLICY_REJECTED,
    HARD_ALLOWED_HOSTS,
    HARD_ALLOWED_START_MS,
    HARD_ALLOWED_STREAMS,
    HARD_ALLOWED_SYMBOLS,
    HARD_OOS_FORBIDDEN_START_MS,
    CollectorError,
)
from .io_utils import sha256_file_from_disk, validate_safe_input_file
from .time_utils import format_utc_ms, iter_months, month_bounds_ms, parse_iso_utc_to_ms


def _require_dict(parent: Dict[str, Any], key: str) -> Dict[str, Any]:
    val = parent.get(key)
    if not isinstance(val, dict):
        raise CollectorError(
            "BLOCKED_INVALID_CONFIG_SCHEMA",
            f"Config section '{key}' must be an object.",
            EXIT_POLICY_REJECTED,
        )
    return val


def _require_strict_int(parent: Dict[str, Any], key: str, *, min_val: int, max_val: int) -> int:
    val = parent.get(key)
    if isinstance(val, bool) or not isinstance(val, int):
        raise CollectorError(
            "BLOCKED_INVALID_CONFIG_SCHEMA",
            f"Config field '{key}' must be an integer, got {val!r}.",
            EXIT_POLICY_REJECTED,
        )
    if not (min_val <= val <= max_val):
        raise CollectorError(
            "BLOCKED_INVALID_CONFIG_VALUE",
            f"Config field '{key}'={val} outside allowed range [{min_val}, {max_val}].",
            EXIT_POLICY_REJECTED,
        )
    return val


def _require_strict_number(parent: Dict[str, Any], key: str, *, min_val: float, max_val: float) -> float:
    val = parent.get(key)
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise CollectorError(
            "BLOCKED_INVALID_CONFIG_SCHEMA",
            f"Config field '{key}' must be numeric, got {val!r}.",
            EXIT_POLICY_REJECTED,
        )
    fval = float(val)
    if not (min_val <= fval <= max_val):
        raise CollectorError(
            "BLOCKED_INVALID_CONFIG_VALUE",
            f"Config field '{key}'={fval} outside allowed range [{min_val}, {max_val}].",
            EXIT_POLICY_REJECTED,
        )
    return fval


def _require_strict_bool(parent: Dict[str, Any], key: str, *, expected: bool) -> bool:
    val = parent.get(key)
    if type(val) is not bool:
        raise CollectorError(
            "BLOCKED_INVALID_CONFIG_SCHEMA",
            f"Config field '{key}' must be boolean, got {val!r}.",
            EXIT_POLICY_REJECTED,
        )
    if val is not expected:
        raise CollectorError(
            "BLOCKED_POLICY_VIOLATION",
            f"Governance/validation field '{key}' must be {expected}, got {val}.",
            EXIT_POLICY_REJECTED,
        )
    return val


def _require_nonempty_str(parent: Dict[str, Any], key: str) -> str:
    val = parent.get(key)
    if not isinstance(val, str) or not val.strip():
        raise CollectorError(
            "BLOCKED_INVALID_CONFIG_SCHEMA",
            f"Config field '{key}' must be a non-empty string.",
            EXIT_POLICY_REJECTED,
        )
    return val.strip()


def _validate_base_url(raw_url: Any, allowed_hosts: Tuple[str, ...], key: str) -> str:
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise CollectorError(
            "BLOCKED_INVALID_CONFIG_SCHEMA",
            f"Base URL '{key}' must be a non-empty string.",
            EXIT_POLICY_REJECTED,
        )
    cleaned = raw_url.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(cleaned)
    if parsed.scheme.lower() != "https":
        raise CollectorError(
            "BLOCKED_DISALLOWED_SCHEME",
            f"Non-HTTPS base URL rejected for '{key}': {raw_url!r}",
            EXIT_POLICY_REJECTED,
        )
    if parsed.username or parsed.password:
        raise CollectorError(
            "BLOCKED_CREDENTIALS_IN_URL",
            f"Credentials in base URL rejected for '{key}': {raw_url!r}",
            EXIT_POLICY_REJECTED,
        )
    host = (parsed.hostname or "").lower()
    if host not in allowed_hosts:
        raise CollectorError(
            "BLOCKED_DISALLOWED_DOMAIN",
            f"Host '{host}' in '{key}' is not in allowed_hosts {allowed_hosts}.",
            EXIT_POLICY_REJECTED,
        )
    if parsed.query or parsed.fragment:
        raise CollectorError(
            "BLOCKED_INVALID_CONFIG_VALUE",
            f"Base URL '{key}' must not include query or fragment: {raw_url!r}",
            EXIT_POLICY_REJECTED,
        )
    return cleaned


@dataclass(frozen=True)
class CollectorConfig:
    """Validated immutable configuration loaded from disk."""

    config_path: str
    config_sha256: str
    run_id: str
    mode_label: str
    symbols: Tuple[str, ...]
    allowed_symbols: Tuple[str, ...]
    streams: Tuple[str, ...]
    start_month: str
    end_month: str
    months: Tuple[str, ...]
    requested_start_utc: str
    requested_start_ms: int
    requested_end_exclusive_utc: str
    requested_end_exclusive_ms: int
    allowed_start_utc: str
    allowed_start_ms: int
    oos_forbidden_start_utc: str
    oos_forbidden_start_ms: int
    allowed_hosts: Tuple[str, ...]
    vision_base_url: str
    fapi_base_url: str
    fetch_exchange_metadata: bool
    connect_timeout_seconds: float
    read_timeout_seconds: float
    max_retries: int
    retry_backoff_base_seconds: float
    retry_backoff_max_seconds: float
    max_retry_after_seconds: float
    funding_page_limit: int
    max_funding_pages_per_month: int
    max_funding_requests_per_5min: int
    max_used_weight_1m: int
    max_http_requests: int
    max_compressed_download_bytes: int
    max_single_response_bytes: int
    max_single_uncompressed_bytes: int
    max_total_storage_bytes: int
    max_wall_time_seconds: float
    budget_rationale: str
    expected_timestamp_unit: str
    require_settlement_mark_price: bool
    assume_fixed_8h_funding: bool
    require_archive_checksum: bool
    anomalous_funding_interval_warning_hours: float
    raw_dict: Dict[str, Any]


def load_and_validate_config(config_path_raw: str | Path) -> CollectorConfig:
    """Load config JSON from disk and enforce all symbol, period, host, retry, and budget rules."""
    cfg_path = validate_safe_input_file(str(config_path_raw), label="config file")
    cfg_sha256, _cfg_bytes = sha256_file_from_disk(cfg_path)
    raw_bytes = cfg_path.read_bytes()
    try:
        raw_dict = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollectorError(
            "BLOCKED_INVALID_CONFIG_JSON",
            f"Invalid JSON in config file {cfg_path}: {exc}",
            EXIT_POLICY_REJECTED,
        ) from exc

    if not isinstance(raw_dict, dict):
        raise CollectorError(
            "BLOCKED_INVALID_CONFIG_SCHEMA",
            "Top-level config payload must be a JSON object.",
            EXIT_POLICY_REJECTED,
        )
    if raw_dict.get("schema_version") != CONFIG_SCHEMA_VERSION:
        raise CollectorError(
            "BLOCKED_INVALID_CONFIG_SCHEMA",
            f"Unsupported config schema_version={raw_dict.get('schema_version')!r}, expected {CONFIG_SCHEMA_VERSION!r}",
            EXIT_POLICY_REJECTED,
        )

    run_id = raw_dict.get("run_id")
    mode_label = raw_dict.get("mode_label")
    if not isinstance(run_id, str) or not run_id.strip():
        raise CollectorError("BLOCKED_INVALID_CONFIG_SCHEMA", "run_id must be a non-empty string.", EXIT_POLICY_REJECTED)
    if not isinstance(mode_label, str) or not mode_label.strip():
        raise CollectorError("BLOCKED_INVALID_CONFIG_SCHEMA", "mode_label must be a non-empty string.", EXIT_POLICY_REJECTED)

    universe = _require_dict(raw_dict, "universe")
    allowed_syms_raw = universe.get("allowed_symbols")
    symbols_raw = universe.get("symbols")
    if not isinstance(allowed_syms_raw, list) or not allowed_syms_raw:
        raise CollectorError("BLOCKED_INVALID_CONFIG_SCHEMA", "universe.allowed_symbols must be a non-empty list.", EXIT_POLICY_REJECTED)
    if not isinstance(symbols_raw, list) or not symbols_raw:
        raise CollectorError("BLOCKED_INVALID_CONFIG_SCHEMA", "universe.symbols must be a non-empty list.", EXIT_POLICY_REJECTED)

    allowed_syms = tuple(str(s) for s in allowed_syms_raw)
    if len(set(allowed_syms)) != len(allowed_syms) or not set(allowed_syms).issubset(set(HARD_ALLOWED_SYMBOLS)):
        raise CollectorError(
            "BLOCKED_DISALLOWED_SYMBOL",
            f"universe.allowed_symbols contains duplicate or disallowed symbol: {allowed_syms}",
            EXIT_POLICY_REJECTED,
        )

    symbols = tuple(str(s) for s in symbols_raw)
    if len(set(symbols)) != len(symbols):
        raise CollectorError(
            "BLOCKED_INVALID_CONFIG_SCHEMA",
            f"Duplicate symbol in universe.symbols: {symbols}",
            EXIT_POLICY_REJECTED,
        )
    disallowed_syms = [s for s in symbols if s not in allowed_syms or s not in HARD_ALLOWED_SYMBOLS]
    if disallowed_syms:
        raise CollectorError(
            "BLOCKED_DISALLOWED_SYMBOL",
            f"Symbol(s) {disallowed_syms} rejected by universe allowlist {HARD_ALLOWED_SYMBOLS}.",
            EXIT_POLICY_REJECTED,
        )

    streams_raw = raw_dict.get("streams")
    if not isinstance(streams_raw, list) or not streams_raw:
        raise CollectorError("BLOCKED_INVALID_CONFIG_SCHEMA", "streams must be a non-empty list.", EXIT_POLICY_REJECTED)
    streams = tuple(str(s) for s in streams_raw)
    if len(set(streams)) != len(streams) or not set(streams).issubset(set(HARD_ALLOWED_STREAMS)):
        raise CollectorError(
            "BLOCKED_DISALLOWED_STREAM",
            f"Invalid or duplicate stream(s) {streams}; allowed={HARD_ALLOWED_STREAMS}",
            EXIT_POLICY_REJECTED,
        )

    period = _require_dict(raw_dict, "period")
    start_month = str(period.get("start_month", ""))
    end_month = str(period.get("end_month", ""))
    months = tuple(iter_months(start_month, end_month))

    allowed_start_utc = str(period.get("allowed_start_utc", ""))
    oos_forbidden_start_utc = str(period.get("oos_forbidden_start_utc", ""))
    allowed_start_ms = parse_iso_utc_to_ms(allowed_start_utc)
    oos_forbidden_start_ms = parse_iso_utc_to_ms(oos_forbidden_start_utc)

    if allowed_start_ms < HARD_ALLOWED_START_MS:
        raise CollectorError(
            "BLOCKED_UNCLEAR_LOWER_BOUNDARY",
            f"period.allowed_start_utc={allowed_start_utc} precedes confirmed lower boundary {HARD_ALLOWED_START_MS} ms.",
            EXIT_POLICY_REJECTED,
        )
    if oos_forbidden_start_ms > HARD_OOS_FORBIDDEN_START_MS:
        raise CollectorError(
            "BLOCKED_OOS_BOUNDARY_RELAXATION_FORBIDDEN",
            f"period.oos_forbidden_start_utc={oos_forbidden_start_utc} exceeds sealed OOS boundary {HARD_OOS_FORBIDDEN_START_MS} ms.",
            EXIT_POLICY_REJECTED,
        )
    if allowed_start_ms >= oos_forbidden_start_ms:
        raise CollectorError(
            "BLOCKED_INVALID_PERIOD_RANGE",
            "allowed_start_utc must be strictly earlier than oos_forbidden_start_utc.",
            EXIT_POLICY_REJECTED,
        )

    first_month_start_ms, _, first_month_next_ms = month_bounds_ms(start_month)
    last_month_start_ms, _, last_month_next_ms = month_bounds_ms(end_month)
    requested_start_utc = _require_nonempty_str(period, "requested_start_utc")
    requested_end_exclusive_utc = _require_nonempty_str(period, "requested_end_exclusive_utc")
    requested_start_ms = parse_iso_utc_to_ms(requested_start_utc)
    requested_end_exclusive_ms = parse_iso_utc_to_ms(requested_end_exclusive_utc)

    if first_month_start_ms < allowed_start_ms or requested_start_ms < allowed_start_ms:
        raise CollectorError(
            "BLOCKED_UNCLEAR_LOWER_BOUNDARY",
            (
                f"Requested start '{start_month}' / '{requested_start_utc}' precedes allowed_start_utc "
                f"'{allowed_start_utc}' (unclear lower boundary rejected)."
            ),
            EXIT_POLICY_REJECTED,
        )
    if requested_start_ms >= requested_end_exclusive_ms:
        raise CollectorError(
            "BLOCKED_INVALID_PERIOD_RANGE",
            f"requested_start_utc '{requested_start_utc}' must be < requested_end_exclusive_utc '{requested_end_exclusive_utc}'.",
            EXIT_POLICY_REJECTED,
        )
    if requested_end_exclusive_ms >= oos_forbidden_start_ms:
        raise CollectorError(
            "BLOCKED_OOS_FORBIDDEN_PERIOD",
            f"requested_end_exclusive_utc '{requested_end_exclusive_utc}' touches or crosses sealed OOS forbidden boundary '{oos_forbidden_start_utc}'.",
            EXIT_POLICY_REJECTED,
        )
    if last_month_next_ms >= oos_forbidden_start_ms:
        raise CollectorError(
            "BLOCKED_OOS_FORBIDDEN_PERIOD",
            (
                f"Full monthly archive scope '{start_month}'..'{end_month}' (upper bound {format_utc_ms(last_month_next_ms)}) "
                f"touches or crosses sealed OOS forbidden boundary '{oos_forbidden_start_utc}'; "
                "post-download filtering cannot substitute for pre-transport OOS rejection."
            ),
            EXIT_POLICY_REJECTED,
        )
    if not (first_month_start_ms <= requested_start_ms < first_month_next_ms) or not (
        last_month_start_ms < requested_end_exclusive_ms <= last_month_next_ms
    ):
        raise CollectorError(
            "BLOCKED_INVALID_PERIOD_RANGE",
            (
                f"Month span '{start_month}'..'{end_month}' must tightly bracket "
                f"[{requested_start_utc}, {requested_end_exclusive_utc})."
            ),
            EXIT_POLICY_REJECTED,
        )

    endpoints = _require_dict(raw_dict, "endpoints")
    hosts_raw = endpoints.get("allowed_hosts")
    if not isinstance(hosts_raw, list) or not hosts_raw:
        raise CollectorError("BLOCKED_INVALID_CONFIG_SCHEMA", "endpoints.allowed_hosts must be a non-empty list.", EXIT_POLICY_REJECTED)
    allowed_hosts = tuple(str(h).lower() for h in hosts_raw)
    if len(set(allowed_hosts)) != len(allowed_hosts) or not set(allowed_hosts).issubset(set(HARD_ALLOWED_HOSTS)):
        raise CollectorError(
            "BLOCKED_DISALLOWED_DOMAIN",
            f"endpoints.allowed_hosts {allowed_hosts} contains disallowed host; hard allowlist={HARD_ALLOWED_HOSTS}",
            EXIT_POLICY_REJECTED,
        )
    vision_base_url = _validate_base_url(endpoints.get("vision_base_url"), allowed_hosts, "vision_base_url")
    fapi_base_url = _validate_base_url(endpoints.get("fapi_base_url"), allowed_hosts, "fapi_base_url")
    fetch_meta_raw = endpoints.get("fetch_exchange_metadata", True)
    if type(fetch_meta_raw) is not bool:
        raise CollectorError("BLOCKED_INVALID_CONFIG_SCHEMA", "endpoints.fetch_exchange_metadata must be boolean.", EXIT_POLICY_REJECTED)

    net = _require_dict(raw_dict, "network_and_retry")
    connect_timeout = _require_strict_number(net, "connect_timeout_seconds", min_val=0.1, max_val=120.0)
    read_timeout = _require_strict_number(net, "read_timeout_seconds", min_val=0.1, max_val=120.0)
    max_retries = _require_strict_int(net, "max_retries", min_val=0, max_val=10)
    backoff_base = _require_strict_number(net, "retry_backoff_base_seconds", min_val=0.001, max_val=60.0)
    backoff_max = _require_strict_number(net, "retry_backoff_max_seconds", min_val=backoff_base, max_val=300.0)
    max_retry_after = _require_strict_number(net, "max_retry_after_seconds", min_val=0.1, max_val=300.0)
    funding_page_limit = _require_strict_int(net, "funding_page_limit", min_val=1, max_val=1000)
    max_funding_pages_per_month = _require_strict_int(net, "max_funding_pages_per_month", min_val=1, max_val=20)
    max_funding_5m = _require_strict_int(net, "max_funding_requests_per_5min", min_val=1, max_val=500)
    max_used_weight_1m = _require_strict_int(net, "max_used_weight_1m", min_val=1, max_val=2400)

    budgets = _require_dict(raw_dict, "budgets")
    max_http_requests = _require_strict_int(budgets, "max_http_requests", min_val=1, max_val=100_000)
    max_compressed_download_bytes = _require_strict_int(budgets, "max_compressed_download_bytes", min_val=1024, max_val=10_737_418_240)
    max_single_response_bytes = _require_strict_int(budgets, "max_single_response_bytes", min_val=1024, max_val=max_compressed_download_bytes)
    max_single_uncompressed_bytes = _require_strict_int(budgets, "max_single_uncompressed_bytes", min_val=1024, max_val=2_147_483_648)
    max_total_storage_bytes = _require_strict_int(budgets, "max_total_storage_bytes", min_val=max_single_uncompressed_bytes, max_val=53_687_091_200)
    max_wall_time_seconds = _require_strict_number(budgets, "max_wall_time_seconds", min_val=0.05, max_val=86_400.0)
    budget_rationale = _require_nonempty_str(budgets, "budget_rationale")

    validation = _require_dict(raw_dict, "validation")
    ts_unit = str(validation.get("expected_timestamp_unit", ""))
    if ts_unit != "ms":
        raise CollectorError(
            "BLOCKED_INVALID_CONFIG_VALUE",
            f"validation.expected_timestamp_unit must be 'ms' for Binance USD-M Futures, got {ts_unit!r}",
            EXIT_POLICY_REJECTED,
        )
    req_mp = _require_strict_bool(validation, "require_settlement_mark_price", expected=True)
    assume_8h = _require_strict_bool(validation, "assume_fixed_8h_funding", expected=False)
    req_cs = _require_strict_bool(validation, "require_archive_checksum", expected=True)
    anomalous_funding_warning_h = _require_strict_number(
        validation,
        "anomalous_funding_interval_warning_hours",
        min_val=8.5,
        max_val=72.0,
    )

    governance = _require_dict(raw_dict, "governance")
    _require_strict_bool(governance, "production_blocked", expected=True)
    _require_strict_bool(governance, "public_market_data_only", expected=True)
    _require_strict_bool(governance, "allow_credentials", expected=False)
    _require_strict_bool(governance, "allow_order_endpoints", expected=False)
    _require_strict_bool(governance, "allow_paid_services", expected=False)

    return CollectorConfig(
        config_path=str(cfg_path),
        config_sha256=cfg_sha256,
        run_id=run_id.strip(),
        mode_label=mode_label.strip(),
        symbols=symbols,
        allowed_symbols=allowed_syms,
        streams=streams,
        start_month=start_month,
        end_month=end_month,
        months=months,
        requested_start_utc=requested_start_utc,
        requested_start_ms=requested_start_ms,
        requested_end_exclusive_utc=requested_end_exclusive_utc,
        requested_end_exclusive_ms=requested_end_exclusive_ms,
        allowed_start_utc=allowed_start_utc,
        allowed_start_ms=allowed_start_ms,
        oos_forbidden_start_utc=oos_forbidden_start_utc,
        oos_forbidden_start_ms=oos_forbidden_start_ms,
        allowed_hosts=allowed_hosts,
        vision_base_url=vision_base_url,
        fapi_base_url=fapi_base_url,
        fetch_exchange_metadata=fetch_meta_raw,
        connect_timeout_seconds=connect_timeout,
        read_timeout_seconds=read_timeout,
        max_retries=max_retries,
        retry_backoff_base_seconds=backoff_base,
        retry_backoff_max_seconds=backoff_max,
        max_retry_after_seconds=max_retry_after,
        funding_page_limit=funding_page_limit,
        max_funding_pages_per_month=max_funding_pages_per_month,
        max_funding_requests_per_5min=max_funding_5m,
        max_used_weight_1m=max_used_weight_1m,
        max_http_requests=max_http_requests,
        max_compressed_download_bytes=max_compressed_download_bytes,
        max_single_response_bytes=max_single_response_bytes,
        max_single_uncompressed_bytes=max_single_uncompressed_bytes,
        max_total_storage_bytes=max_total_storage_bytes,
        max_wall_time_seconds=max_wall_time_seconds,
        budget_rationale=budget_rationale,
        expected_timestamp_unit=ts_unit,
        require_settlement_mark_price=req_mp,
        assume_fixed_8h_funding=assume_8h,
        require_archive_checksum=req_cs,
        anomalous_funding_interval_warning_hours=anomalous_funding_warning_h,
        raw_dict=raw_dict,
    )
