"""Deterministic synthetic Binance Futures payloads and mock HTTPS transport for offline tests."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import urllib.parse
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from collector.constants import HARD_ALLOWED_SYMBOLS, STREAM_TO_VISION_PATH_SPEC
from collector.time_utils import format_utc_ms, month_bounds_ms
from collector.transport import HttpResponse


def make_synthetic_config(
    *,
    symbols: Optional[List[str]] = None,
    streams: Optional[List[str]] = None,
    start_month: str = "2024-01",
    end_month: str = "2024-01",
    requested_start_utc: Optional[str] = None,
    requested_end_exclusive_utc: Optional[str] = None,
    allowed_start_utc: str = "2021-01-01T00:00:00Z",
    oos_forbidden_start_utc: str = "2025-10-13T00:00:00Z",
    allowed_hosts: Optional[List[str]] = None,
    vision_base_url: str = "https://data.binance.vision",
    fapi_base_url: str = "https://fapi.binance.com",
    fetch_exchange_metadata: bool = True,
    max_retries: int = 2,
    retry_backoff_base_seconds: float = 0.25,
    retry_backoff_max_seconds: float = 2.0,
    max_retry_after_seconds: float = 5.0,
    funding_page_limit: int = 1000,
    max_funding_pages_per_month: int = 5,
    max_funding_requests_per_5min: int = 400,
    max_used_weight_1m: int = 2000,
    max_http_requests: int = 200,
    max_compressed_download_bytes: int = 50_000_000,
    max_single_response_bytes: int = 10_000_000,
    max_single_uncompressed_bytes: int = 20_000_000,
    max_total_storage_bytes: int = 100_000_000,
    max_wall_time_seconds: float = 300.0,
    budget_rationale: str = "Offline synthetic test execution budget.",
    anomalous_funding_interval_warning_hours: float = 10.0,
) -> Dict[str, Any]:
    if requested_start_utc is None:
        try:
            ms_start, _, _ = month_bounds_ms(start_month)
            requested_start_utc = format_utc_ms(ms_start)
        except Exception:
            requested_start_utc = allowed_start_utc
    if requested_end_exclusive_utc is None:
        try:
            _, _, ms_next = month_bounds_ms(end_month)
            requested_end_exclusive_utc = format_utc_ms(ms_next)
        except Exception:
            requested_end_exclusive_utc = "2024-02-01T00:00:00Z"

    return {
        "schema_version": "cloud_collector_config_v1",
        "run_id": "SYNTHETIC_TEST_RUN",
        "mode_label": "SYNTHETIC_OFFLINE_TEST",
        "universe": {
            "allowed_symbols": list(HARD_ALLOWED_SYMBOLS),
            "symbols": symbols if symbols is not None else ["BTCUSDT", "ETHUSDT"],
        },
        "streams": streams if streams is not None else ["exec_15m", "mark_1h", "funding_settlement"],
        "period": {
            "start_month": start_month,
            "end_month": end_month,
            "requested_start_utc": requested_start_utc,
            "requested_end_exclusive_utc": requested_end_exclusive_utc,
            "allowed_start_utc": allowed_start_utc,
            "oos_forbidden_start_utc": oos_forbidden_start_utc,
        },
        "endpoints": {
            "allowed_hosts": allowed_hosts if allowed_hosts is not None else ["data.binance.vision", "fapi.binance.com"],
            "vision_base_url": vision_base_url,
            "fapi_base_url": fapi_base_url,
            "fetch_exchange_metadata": fetch_exchange_metadata,
        },
        "network_and_retry": {
            "connect_timeout_seconds": 5.0,
            "read_timeout_seconds": 10.0,
            "max_retries": max_retries,
            "retry_backoff_base_seconds": retry_backoff_base_seconds,
            "retry_backoff_max_seconds": retry_backoff_max_seconds,
            "max_retry_after_seconds": max_retry_after_seconds,
            "funding_page_limit": funding_page_limit,
            "max_funding_pages_per_month": max_funding_pages_per_month,
            "max_funding_requests_per_5min": max_funding_requests_per_5min,
            "max_used_weight_1m": max_used_weight_1m,
        },
        "budgets": {
            "max_http_requests": max_http_requests,
            "max_compressed_download_bytes": max_compressed_download_bytes,
            "max_single_response_bytes": max_single_response_bytes,
            "max_single_uncompressed_bytes": max_single_uncompressed_bytes,
            "max_total_storage_bytes": max_total_storage_bytes,
            "max_wall_time_seconds": max_wall_time_seconds,
            "budget_rationale": budget_rationale,
        },
        "validation": {
            "expected_timestamp_unit": "ms",
            "require_settlement_mark_price": True,
            "assume_fixed_8h_funding": False,
            "require_archive_checksum": True,
            "anomalous_funding_interval_warning_hours": anomalous_funding_interval_warning_hours,
        },
        "governance": {
            "production_blocked": True,
            "public_market_data_only": True,
            "allow_credentials": False,
            "allow_order_endpoints": False,
            "allow_paid_services": False,
        },
    }


def write_config_file(path: Path, cfg: Dict[str, Any]) -> Path:
    path.write_bytes((json.dumps(cfg, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return path


def build_kline_zip_and_checksum(
    symbol: str,
    interval: str,
    ym: str,
    *,
    with_header: bool = True,
    base_price: float = 40000.0,
    start_override_ms: Optional[int] = None,
    skip_indices: Optional[set[int]] = None,
    duplicate_index: Optional[int] = None,
    conflicting_duplicate_index: Optional[int] = None,
    ts_multiplier: int = 1,
    ts_divisor: int = 1,
    corrupt_ohlc_at: Optional[int] = None,
    extra_row_open_ms: Optional[int] = None,
) -> Tuple[bytes, bytes]:
    interval_ms = 900_000 if interval == "15m" else 3_600_000
    m_start_ms, m_end_ms, _ = month_bounds_ms(ym)
    effective_start = start_override_ms if start_override_ms is not None else m_start_ms
    aligned_start = ((effective_start + interval_ms - 1) // interval_ms) * interval_ms

    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    if with_header:
        writer.writerow(
            [
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
            ]
        )

    cur = aligned_start
    idx = 0
    while cur <= m_end_ms:
        if skip_indices and idx in skip_indices:
            cur += interval_ms
            idx += 1
            continue
        p0 = base_price + (idx % 50) * 1.25
        hi = p0 + 15.0
        lo = p0 - 12.0
        cl = p0 + 3.0
        if corrupt_ohlc_at is not None and idx == corrupt_ohlc_at:
            hi = p0 - 20.0  # invalid high < low
        o_ts = (cur * ts_multiplier) // ts_divisor
        c_ts = ((cur + interval_ms - 1) * ts_multiplier) // ts_divisor
        row = [
            o_ts,
            f"{p0:.2f}",
            f"{hi:.2f}",
            f"{lo:.2f}",
            f"{cl:.2f}",
            "12.500",
            c_ts,
            "500000.00",
            120,
            "6.250",
            "250000.00",
            "0",
        ]
        writer.writerow(row)
        if duplicate_index is not None and idx == duplicate_index:
            writer.writerow(row)
        if conflicting_duplicate_index is not None and idx == conflicting_duplicate_index:
            conflict_row = list(row)
            conflict_row[4] = f"{cl + 9.0:.2f}"
            writer.writerow(conflict_row)
        cur += interval_ms
        idx += 1

    if extra_row_open_ms is not None:
        writer.writerow(
            [
                extra_row_open_ms,
                f"{base_price:.2f}",
                f"{base_price + 10:.2f}",
                f"{base_price - 10:.2f}",
                f"{base_price + 1:.2f}",
                "1.0",
                extra_row_open_ms + interval_ms - 1,
                "40000.0",
                5,
                "0.5",
                "20000.0",
                "0",
            ]
        )

    csv_name = f"{symbol}-{interval}-{ym}.csv"
    zip_name = f"{symbol}-{interval}-{ym}.zip"
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(csv_name, buf.getvalue().encode("utf-8"))
    zip_bytes = zip_buf.getvalue()
    digest = hashlib.sha256(zip_bytes).hexdigest()
    checksum_bytes = f"{digest}  {zip_name}\n".encode("utf-8")
    return zip_bytes, checksum_bytes


def build_funding_events_for_month(
    symbol: str,
    ym: str,
    *,
    start_override_ms: Optional[int] = None,
    interval_hours: int = 8,
    subsecond_offset_ms: int = 0,
    base_mark_price: float = 40100.0,
    missing_mark_indices: Optional[set[int]] = None,
    null_mark_indices: Optional[set[int]] = None,
    empty_mark_indices: Optional[set[int]] = None,
    zero_mark_indices: Optional[set[int]] = None,
    skip_indices: Optional[set[int]] = None,
    ts_multiplier: int = 1,
    ts_divisor: int = 1,
) -> List[Dict[str, Any]]:
    m_start_ms, m_end_ms, _ = month_bounds_ms(ym)
    step_ms = interval_hours * 3_600_000
    cur = start_override_ms if start_override_ms is not None else m_start_ms
    if cur > m_start_ms and cur % step_ms != 0:
        cur = ((cur + step_ms - 1) // step_ms) * step_ms
    out: List[Dict[str, Any]] = []
    idx = 0
    while cur <= m_end_ms:
        if skip_indices and idx in skip_indices:
            cur += step_ms
            idx += 1
            continue
        ts = cur + (subsecond_offset_ms if idx % 3 == 1 else 0)
        ts_val = (ts * ts_multiplier) // ts_divisor
        ev: Dict[str, Any] = {
            "symbol": symbol,
            "fundingTime": ts_val,
            "fundingRate": "0.00010000" if idx % 2 == 0 else "-0.00005000",
        }
        if missing_mark_indices and idx in missing_mark_indices:
            pass
        elif null_mark_indices and idx in null_mark_indices:
            ev["markPrice"] = None
        elif empty_mark_indices and idx in empty_mark_indices:
            ev["markPrice"] = ""
        elif zero_mark_indices and idx in zero_mark_indices:
            ev["markPrice"] = "0.00000000"
        else:
            ev["markPrice"] = f"{base_mark_price + (idx % 20) * 5.0:.8f}"
        out.append(ev)
        cur += step_ms
        idx += 1
    return out


class SyntheticBinanceServer:
    """In-memory programmable Binance Vision + FAPI mock transport."""

    def __init__(
        self,
        *,
        onboard_dates_ms: Optional[Dict[str, int]] = None,
        funding_info: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self.onboard_dates_ms = onboard_dates_ms or {s: 1577836800000 for s in HARD_ALLOWED_SYMBOLS}  # 2020-01-01
        self.funding_info = funding_info or []
        self.vision_archives: Dict[Tuple[str, str, str], Tuple[bytes, bytes]] = {}
        self.funding_events: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        self.requests_seen: List[str] = []
        self.override_handler: Optional[Callable[[str, int], Optional[HttpResponse]]] = None
        self.exception_handler: Optional[Callable[[str, int], None]] = None

    def register_month_all_streams(self, symbol: str, ym: str, *, base_price: float = 40000.0) -> None:
        onboard = self.onboard_dates_ms.get(symbol)
        m_start, m_end, _ = month_bounds_ms(ym)
        if onboard is not None and m_end < onboard:
            return
        start_override = onboard if (onboard is not None and m_start < onboard <= m_end) else None
        for stream, (ds_type, interval) in STREAM_TO_VISION_PATH_SPEC.items():
            zb, cs = build_kline_zip_and_checksum(
                symbol,
                interval,
                ym,
                base_price=base_price,
                start_override_ms=start_override,
            )
            self.vision_archives[(ds_type, symbol, ym)] = (zb, cs)
        self.funding_events[(symbol, ym)] = build_funding_events_for_month(
            symbol,
            ym,
            start_override_ms=start_override,
            base_mark_price=base_price,
        )

    def __call__(
        self,
        url: str,
        _connect_timeout: float,
        _read_timeout: float,
        _max_bytes: int,
        _allowed_hosts: Tuple[str, ...],
    ) -> HttpResponse:
        call_num = len(self.requests_seen) + 1
        self.requests_seen.append(url)
        if self.exception_handler is not None:
            self.exception_handler(url, call_num)
        if self.override_handler is not None:
            overridden = self.override_handler(url, call_num)
            if overridden is not None:
                return overridden

        parsed = urllib.parse.urlsplit(url)
        host = (parsed.hostname or "").lower()
        if host == "fapi.binance.com":
            if parsed.path == "/fapi/v1/exchangeInfo":
                payload = {
                    "symbols": [
                        {"symbol": sym, "status": "TRADING", "onboardDate": ts}
                        for sym, ts in self.onboard_dates_ms.items()
                    ]
                }
                return HttpResponse(200, {"x-mbx-used-weight-1m": "1"}, json.dumps(payload).encode("utf-8"), url)
            if parsed.path == "/fapi/v1/fundingInfo":
                return HttpResponse(200, {"x-mbx-used-weight-1m": "1"}, json.dumps(self.funding_info).encode("utf-8"), url)
            if parsed.path == "/fapi/v1/fundingRate":
                qs = urllib.parse.parse_qs(parsed.query)
                sym = qs["symbol"][0]
                s_ms = int(qs["startTime"][0])
                e_ms = int(qs["endTime"][0])
                lim = int(qs.get("limit", ["100"])[0])
                # Collect all registered events matching [s_ms, e_ms]
                matched: List[Dict[str, Any]] = []
                for (esym, _ym), evs in sorted(self.funding_events.items()):
                    if esym == sym:
                        for ev in evs:
                            ft_val = int(ev["fundingTime"])
                            if not (1_000_000_000_000 <= ft_val < 10_000_000_000_000) or (s_ms <= ft_val <= e_ms):
                                matched.append(ev)
                matched.sort(key=lambda x: int(x["fundingTime"]))
                page = matched[:lim]
                return HttpResponse(200, {"x-mbx-used-weight-1m": "2"}, json.dumps(page).encode("utf-8"), url)
        elif host == "data.binance.vision":
            # /data/futures/um/monthly/{ds_type}/{sym}/{interval}/{sym}-{interval}-{ym}.zip(.CHECKSUM)
            parts = parsed.path.strip("/").split("/")
            if len(parts) == 8:
                ds_type, sym, _interval, fname = parts[4], parts[5], parts[6], parts[7]
                is_cs = fname.endswith(".CHECKSUM")
                base_name = fname[:-9] if is_cs else fname
                ym = "-".join(base_name[:-4].split("-")[-2:])
                key = (ds_type, sym, ym)
                if key not in self.vision_archives:
                    return HttpResponse(404, {}, b"Not Found", url)
                zb, cs = self.vision_archives[key]
                return HttpResponse(200, {}, cs if is_cs else zb, url)

        return HttpResponse(404, {}, b"Not Found", url)
