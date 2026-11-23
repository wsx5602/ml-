"""Comprehensive offline synthetic test suite covering all 8 collector requirements."""

from __future__ import annotations

import contextlib
import datetime as _dt
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.request
import zipfile
from http.client import HTTPMessage
from pathlib import Path
from typing import Any, List, Optional
from urllib.response import addinfourl

from collector.cli import main as cli_main
from collector.config import load_and_validate_config
from collector.constants import (
    EXIT_COMPLETE,
    EXIT_INCOMPLETE_DATA,
    EXIT_POLICY_REJECTED,
    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
    OOS_FORBIDDEN_DIR_NAME,
    CollectorError,
)
from collector.engine import run_collect, run_export_bundle, run_preflight, run_verify
from collector.io_utils import sha256_file_from_disk
from collector.time_utils import month_bounds_ms, parse_iso_utc_to_ms
from collector.transport import (
    BudgetTracker,
    HttpResponse,
    RateLimitedClient,
    _NoRedirectHandler,
    build_stdlib_https_transport,
    parse_retry_after_header,
    validate_request_url,
)
from tests.fixtures import (
    SyntheticBinanceServer,
    build_funding_events_for_month,
    build_kline_zip_and_checksum,
    make_synthetic_config,
    write_config_file,
)


class FakeClock:
    def __init__(self, initial: float = 1000.0) -> None:
        self.now = initial
        self.sleeps: List[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class CollectorSyntheticTests(unittest.TestCase):
    """All tests run strictly offline against synthetic responses and TemporaryDirectory."""

    def _package_root(self) -> Path:
        return Path(__file__).resolve().parent.parent

    # ------------------------------------------------------------------
    # 1. Forbidden period / wrong symbol / disallowed domain rejection (0 network calls)
    # ------------------------------------------------------------------
    def test_01_rejects_forbidden_period_symbol_domain_and_payload_oos(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            srv_zero = SyntheticBinanceServer()

            # 1a) OOS months 2025-10 & 2025-11 + post-download OOS filter bypass attempt -> 0 network calls
            for idx, (s_m, e_m, req_s, req_e, tag) in enumerate(
                [
                    ("2025-10", "2025-10", "2025-10-01T00:00:00Z", "2025-11-01T00:00:00Z", "2025_10"),
                    ("2025-11", "2025-11", "2025-11-01T00:00:00Z", "2025-12-01T00:00:00Z", "2025_11"),
                    # Sub-month requested end before OOS inside an OOS-spanning archive MUST fail pre-transport
                    ("2025-10", "2025-10", "2025-10-01T00:00:00Z", "2025-10-12T00:00:00Z", "bypass_filter_2025_10"),
                ]
            ):
                cfg = make_synthetic_config(
                    start_month=s_m,
                    end_month=e_m,
                    requested_start_utc=req_s,
                    requested_end_exclusive_utc=req_e,
                )
                cfg_p = write_config_file(tmp / f"cfg_{tag}.json", cfg)
                with self.assertRaises(CollectorError) as ctx:
                    run_preflight(cfg_p)
                self.assertEqual(ctx.exception.exit_code, EXIT_POLICY_REJECTED)
                self.assertEqual(ctx.exception.code, "BLOCKED_OOS_FORBIDDEN_PERIOD")
                with self.assertRaises(CollectorError) as ctx_c:
                    run_collect(cfg_p, tmp / f"out_zero_{idx}", transport=srv_zero)
                self.assertEqual(ctx_c.exception.code, "BLOCKED_OOS_FORBIDDEN_PERIOD")
                self.assertEqual(srv_zero.requests_seen, [])

            # Archive touching early synthetic OOS boundary at close boundary rejected pre-transport
            cfg_touch = make_synthetic_config(
                start_month="2024-01",
                end_month="2024-01",
                requested_start_utc="2024-01-01T00:00:00Z",
                requested_end_exclusive_utc="2024-02-01T00:00:00Z",
                oos_forbidden_start_utc="2024-02-01T00:00:00Z",
            )
            cfg_touch_p = write_config_file(tmp / "cfg_touch.json", cfg_touch)
            with self.assertRaises(CollectorError) as ctx_touch:
                run_collect(cfg_touch_p, tmp / "out_zero_touch", transport=srv_zero)
            self.assertEqual(ctx_touch.exception.code, "BLOCKED_OOS_FORBIDDEN_PERIOD")
            self.assertEqual(srv_zero.requests_seen, [])

            # 1b) Unclear lower boundary before 2021-01 rejected with 0 network calls
            cfg_old = make_synthetic_config(start_month="2020-12", end_month="2020-12")
            cfg_old_p = write_config_file(tmp / "cfg_2020_12.json", cfg_old)
            with self.assertRaises(CollectorError) as ctx_old:
                run_collect(cfg_old_p, tmp / "out_zero_old", transport=srv_zero)
            self.assertEqual(ctx_old.exception.exit_code, EXIT_POLICY_REJECTED)
            self.assertEqual(ctx_old.exception.code, "BLOCKED_UNCLEAR_LOWER_BOUNDARY")
            self.assertEqual(srv_zero.requests_seen, [])

            # 1c) Disallowed symbol DOGEUSDT rejected with 0 network calls
            cfg_sym = make_synthetic_config(symbols=["BTCUSDT", "DOGEUSDT"])
            cfg_sym_p = write_config_file(tmp / "cfg_bad_sym.json", cfg_sym)
            with self.assertRaises(CollectorError) as ctx_sym:
                run_collect(cfg_sym_p, tmp / "out_zero_sym", transport=srv_zero)
            self.assertEqual(ctx_sym.exception.exit_code, EXIT_POLICY_REJECTED)
            self.assertEqual(ctx_sym.exception.code, "BLOCKED_DISALLOWED_SYMBOL")
            self.assertEqual(srv_zero.requests_seen, [])

            # 1d) Disallowed domain, non-HTTPS, credentials, disallowed endpoint, close-touch Vision archive
            cfg_dom = make_synthetic_config(
                allowed_hosts=["evil.example.com", "fapi.binance.com"],
                vision_base_url="https://evil.example.com",
            )
            cfg_dom_p = write_config_file(tmp / "cfg_bad_dom.json", cfg_dom)
            with self.assertRaises(CollectorError) as ctx_dom:
                run_collect(cfg_dom_p, tmp / "out_zero_dom", transport=srv_zero)
            self.assertEqual(ctx_dom.exception.code, "BLOCKED_DISALLOWED_DOMAIN")
            self.assertEqual(srv_zero.requests_seen, [])

            for bad_url, expected_code in [
                ("http://data.binance.vision/data/futures/um/monthly/klines/BTCUSDT/15m/BTCUSDT-15m-2024-01.zip", "BLOCKED_DISALLOWED_SCHEME"),
                ("https://user:pass@fapi.binance.com/fapi/v1/exchangeInfo", "BLOCKED_CREDENTIALS_IN_URL"),
                ("https://fapi.binance.com/fapi/v1/disallowedEndpoint?symbol=BTCUSDT", "BLOCKED_DISALLOWED_ENDPOINT"),
                ("https://fapi.binance.com/fapi/v1/fundingRate?symbol=BTCUSDT&startTime=1704067200000&endTime=1706745599999&auth=DUMMY", "BLOCKED_API_KEY_IN_REQUEST"),
                ("https://data.binance.vision/data/futures/um/monthly/klines/BTCUSDT/15m/BTCUSDT-15m-2025-10.zip", "BLOCKED_OOS_FORBIDDEN_PERIOD"),
                ("https://data.binance.vision/data/futures/um/monthly/klines/DOGEUSDT/15m/DOGEUSDT-15m-2024-01.zip", "BLOCKED_DISALLOWED_SYMBOL"),
            ]:
                with self.assertRaises(CollectorError) as ctx_u:
                    validate_request_url(
                        bad_url,
                        allowed_hosts=("data.binance.vision", "fapi.binance.com"),
                        allowed_symbols=("BTCUSDT", "ETHUSDT"),
                        allowed_start_ms=parse_iso_utc_to_ms("2021-01-01T00:00:00Z"),
                        oos_forbidden_start_ms=parse_iso_utc_to_ms("2025-10-13T00:00:00Z"),
                    )
                self.assertEqual(ctx_u.exception.code, expected_code, f"URL={bad_url}")

            # Vision URL whose close boundary equals oos_forbidden_start_ms rejected pre-transport
            with self.assertRaises(CollectorError) as ctx_close_u:
                validate_request_url(
                    "https://data.binance.vision/data/futures/um/monthly/klines/BTCUSDT/15m/BTCUSDT-15m-2024-01.zip",
                    allowed_hosts=("data.binance.vision", "fapi.binance.com"),
                    allowed_symbols=("BTCUSDT", "ETHUSDT"),
                    allowed_start_ms=parse_iso_utc_to_ms("2021-01-01T00:00:00Z"),
                    oos_forbidden_start_ms=parse_iso_utc_to_ms("2024-02-01T00:00:00Z"),
                )
            self.assertEqual(ctx_close_u.exception.code, "BLOCKED_OOS_FORBIDDEN_PERIOD")

            # 1e) Untrusted final_url redirect during collect rejected
            srv = SyntheticBinanceServer()
            srv.register_month_all_streams("BTCUSDT", "2024-01")

            def redirect_evil(url: str, _c: float, _r: float, _m: int, _h: tuple) -> HttpResponse:
                return HttpResponse(200, {}, b"{}", "https://evil.example.com/hijack")

            cfg_ok = make_synthetic_config(symbols=["BTCUSDT"], streams=["mark_1h"])
            cfg_ok_p = write_config_file(tmp / "cfg_redir.json", cfg_ok)
            code, res = run_collect(cfg_ok_p, tmp / "out_redir", transport=redirect_evil)
            self.assertEqual(code, EXIT_POLICY_REJECTED)
            self.assertEqual(res["status"], "FAILED")
            self.assertEqual(res["error"]["code"], "BLOCKED_DISALLOWED_DOMAIN")

            # 1f) Payload-level OOS smuggling: kline open_time, kline logical close_time, and funding_time checked separately
            for tag, open_iso in [
                ("open_oos", "2025-10-13T00:00:00Z"),
                # 1h bar open at 23:00Z (< OOS), raw close 23:59:59.999Z (< OOS), logical close == 2025-10-13T00:00:00Z
                ("logical_close_oos", "2025-10-12T23:00:00Z"),
            ]:
                zb_smug, cs_smug = build_kline_zip_and_checksum(
                    "BTCUSDT",
                    "1h",
                    "2024-01",
                    extra_row_open_ms=parse_iso_utc_to_ms(open_iso),
                )
                srv_smug = SyntheticBinanceServer()
                srv_smug.vision_archives[("markPriceKlines", "BTCUSDT", "2024-01")] = (zb_smug, cs_smug)
                cfg_smug_p = write_config_file(tmp / f"cfg_smug_{tag}.json", make_synthetic_config(symbols=["BTCUSDT"], streams=["mark_1h"]))
                code_s, res_s = run_collect(cfg_smug_p, tmp / f"out_smug_{tag}", transport=srv_smug)
                self.assertEqual(code_s, EXIT_RUNTIME_OR_INTEGRITY_ERROR, tag)
                self.assertEqual(res_s["error"]["code"], "FAILED_OOS_CONTAMINATION_IN_PAYLOAD", tag)

            srv_fsmug = SyntheticBinanceServer()
            srv_fsmug.register_month_all_streams("BTCUSDT", "2024-01")
            smug_evs = list(srv_fsmug.funding_events[("BTCUSDT", "2024-01")]) + [
                {
                    "symbol": "BTCUSDT",
                    "fundingTime": parse_iso_utc_to_ms("2025-10-13T00:00:00Z"),
                    "fundingRate": "0.00010000",
                    "markPrice": "42000.00000000",
                }
            ]
            srv_fsmug.override_handler = lambda u, _c: (
                HttpResponse(200, {}, json.dumps(smug_evs).encode("utf-8"), u) if "/fapi/v1/fundingRate" in u else None
            )
            cfg_fsmug_p = write_config_file(tmp / "cfg_fsmug.json", make_synthetic_config(symbols=["BTCUSDT"], streams=["funding_settlement"]))
            code_fs, res_fs = run_collect(cfg_fsmug_p, tmp / "out_fsmug", transport=srv_fsmug)
            self.assertEqual(code_fs, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res_fs["error"]["code"], "FAILED_OOS_CONTAMINATION_IN_PAYLOAD")

            # 1g) Output path containing sealed OOS directory segment rejected
            with self.assertRaises(CollectorError) as ctx_oos_dir:
                run_collect(cfg_ok_p, tmp / OOS_FORBIDDEN_DIR_NAME / "sub", transport=srv)
            self.assertEqual(ctx_oos_dir.exception.code, "BLOCKED_FORBIDDEN_PATH_SEGMENT")

    # ------------------------------------------------------------------
    # 2. Identical vs conflicting duplicates, real gaps, irregular funding & cross-month
    # ------------------------------------------------------------------
    def test_02_page_boundary_duplicate_gap_and_variable_funding_intervals(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            m_start, _m_end, _ = month_bounds_ms("2024-01")
            evs_full = build_funding_events_for_month("BTCUSDT", "2024-01")  # 93 events

            # 2a) Identical page-boundary overlap (page 2 starts with page 1's last event) -> COMPLETE with clean dedup
            srv_dup = SyntheticBinanceServer()
            srv_dup.funding_events[("BTCUSDT", "2024-01")] = evs_full

            def dup_identical_handler(url: str, _call: int):
                if "/fapi/v1/fundingRate" in url:
                    qs = url.split("startTime=")[1]
                    s_val = int(qs.split("&")[0])
                    if s_val == m_start:
                        return HttpResponse(200, {}, json.dumps(evs_full[:50]).encode("utf-8"), url)
                    return HttpResponse(200, {}, json.dumps(evs_full[49:]).encode("utf-8"), url)
                return None

            srv_dup.override_handler = dup_identical_handler
            cfg_p = write_config_file(
                tmp / "cfg_dup.json",
                make_synthetic_config(symbols=["BTCUSDT"], streams=["funding_settlement"], funding_page_limit=50),
            )
            code, res = run_collect(cfg_p, tmp / "out_dup_ok", transport=srv_dup)
            self.assertEqual(code, EXIT_COMPLETE)
            self.assertEqual(res["status"], "COMPLETE")
            manifest = json.loads((tmp / "out_dup_ok" / "manifest.json").read_bytes().decode("utf-8"))
            fu = manifest["units"][0]
            self.assertEqual(fu["page_boundary_identical_duplicate_count"], 1)
            self.assertEqual(fu["conflicting_duplicate_count"], 0)
            self.assertEqual(fu["row_count"], len(evs_full))
            self.assertIsNotNone(fu["refined_artifact"])
            merged_csv = (tmp / "out_dup_ok" / "refined" / "merged" / "BTCUSDT_funding_settlement.csv").read_text(encoding="utf-8")
            self.assertEqual(len(merged_csv.strip().splitlines()), len(evs_full) + 1)

            # 2b) Conflicting duplicate at same timestamp across pages -> FAIL closed (exit 4) with raw preserved
            srv_conflict = SyntheticBinanceServer()
            conflict_ev = dict(evs_full[49])
            conflict_ev["fundingRate"] = "0.00999900"

            def dup_conflict_handler(url: str, _call: int):
                if "/fapi/v1/fundingRate" in url:
                    qs = url.split("startTime=")[1]
                    s_val = int(qs.split("&")[0])
                    if s_val == m_start:
                        return HttpResponse(200, {}, json.dumps(evs_full[:50]).encode("utf-8"), url)
                    return HttpResponse(200, {}, json.dumps([conflict_ev] + evs_full[50:]).encode("utf-8"), url)
                return None

            srv_conflict.override_handler = dup_conflict_handler
            code_c, res_c = run_collect(cfg_p, tmp / "out_conflict", transport=srv_conflict)
            self.assertEqual(code_c, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res_c["error"]["code"], "FAILED_CONFLICTING_DUPLICATE_EVENT")
            manifest_c = json.loads((tmp / "out_conflict" / "manifest.json").read_bytes().decode("utf-8"))
            self.assertEqual(manifest_c["units"][0]["conflicting_duplicate_count"], 1)
            self.assertIsNone(manifest_c["units"][0]["refined_artifact"])
            self.assertEqual(len(manifest_c["units"][0]["raw_artifacts"]), 2)

            # 2c) True funding truncation by max_funding_pages_per_month & empty stream -> INCOMPLETE (exit 3)
            srv_trunc = SyntheticBinanceServer()
            srv_trunc.funding_events[("BTCUSDT", "2024-01")] = evs_full
            cfg_trunc = write_config_file(
                tmp / "cfg_trunc.json",
                make_synthetic_config(
                    symbols=["BTCUSDT"],
                    streams=["funding_settlement"],
                    funding_page_limit=50,
                    max_funding_pages_per_month=1,
                ),
            )
            code_t, _res_t = run_collect(cfg_trunc, tmp / "out_trunc", transport=srv_trunc)
            self.assertEqual(code_t, EXIT_INCOMPLETE_DATA)
            manifest_t = json.loads((tmp / "out_trunc" / "manifest.json").read_bytes().decode("utf-8"))
            self.assertEqual(manifest_t["units"][0]["status"], "INCOMPLETE_MISSING_STREAM_OR_GAPS")
            self.assertGreaterEqual(manifest_t["units"][0]["missing_count"], 1)
            self.assertIsNone(manifest_t["units"][0]["refined_artifact"])

            # 2d) Irregular funding intervals (2h + 12h + 18h cross-month transition + subsecond ms offset) -> COMPLETE
            # Must NOT misclassify variable funding cadence as fixed-8h grid missing bars.
            evs_2h_irreg = build_funding_events_for_month(
                "SOLUSDT",
                "2022-11",
                interval_hours=2,
                subsecond_offset_ms=18,
                skip_indices={100, 101, 102, 103, 104},  # creates a 12h schedule switch
            )
            evs_dec = build_funding_events_for_month("SOLUSDT", "2022-12", interval_hours=8)[2:]  # 18h cross-month transition
            srv_2h = SyntheticBinanceServer()
            srv_2h.funding_events[("SOLUSDT", "2022-11")] = evs_2h_irreg
            srv_2h.funding_events[("SOLUSDT", "2022-12")] = evs_dec
            cfg_2h = write_config_file(
                tmp / "cfg_2h.json",
                make_synthetic_config(
                    symbols=["SOLUSDT"],
                    streams=["funding_settlement"],
                    start_month="2022-11",
                    end_month="2022-12",
                    funding_page_limit=100,
                    max_funding_pages_per_month=5,
                ),
            )
            code_2h, res_2h = run_collect(cfg_2h, tmp / "out_2h", transport=srv_2h)
            self.assertEqual(code_2h, EXIT_COMPLETE)
            self.assertEqual(res_2h["status"], "COMPLETE")
            m2h = json.loads((tmp / "out_2h" / "manifest.json").read_bytes().decode("utf-8"))
            ssum = m2h["stream_summaries"]["SOLUSDT"]["streams"]["funding_settlement"]
            self.assertEqual(ssum["total_rows"], len(evs_2h_irreg) + len(evs_dec))
            self.assertEqual(ssum["missing_count"], 0)
            self.assertGreater(ssum["irregular_interval_count"], 300)
            self.assertGreater(ssum["non_8h_short_interval_count"], 300)
            self.assertGreater(ssum["subsecond_offset_count"], 100)
            self.assertGreaterEqual(ssum["interval_warnings_count"], 2)
            self.assertEqual(m2h["cross_month_defects"], [])

            # 2e) Kline interior missing bar + identical duplicate -> INCOMPLETE exit 3; conflicting bar -> FAILED exit 4
            zb_kgap, cs_kgap = build_kline_zip_and_checksum("BTCUSDT", "1h", "2024-01", skip_indices={12}, duplicate_index=20)
            srv_kgap = SyntheticBinanceServer()
            srv_kgap.vision_archives[("markPriceKlines", "BTCUSDT", "2024-01")] = (zb_kgap, cs_kgap)
            cfg_kgap = write_config_file(tmp / "cfg_kgap.json", make_synthetic_config(symbols=["BTCUSDT"], streams=["mark_1h"]))
            code_kg, _res_kg = run_collect(cfg_kgap, tmp / "out_kgap", transport=srv_kgap)
            self.assertEqual(code_kg, EXIT_INCOMPLETE_DATA)
            m_kg = json.loads((tmp / "out_kgap" / "manifest.json").read_bytes().decode("utf-8"))
            self.assertEqual(m_kg["units"][0]["missing_count"], 1)
            self.assertEqual(m_kg["units"][0]["identical_duplicate_count"], 1)
            self.assertEqual(m_kg["units"][0]["conflicting_duplicate_count"], 0)
            self.assertIsNone(m_kg["units"][0]["refined_artifact"])

            zb_kc, cs_kc = build_kline_zip_and_checksum("BTCUSDT", "1h", "2024-01", conflicting_duplicate_index=20)
            srv_kc = SyntheticBinanceServer()
            srv_kc.vision_archives[("markPriceKlines", "BTCUSDT", "2024-01")] = (zb_kc, cs_kc)
            code_kc, res_kc = run_collect(cfg_kgap, tmp / "out_kc", transport=srv_kc)
            self.assertEqual(code_kc, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res_kc["error"]["code"], "FAILED_CONFLICTING_DUPLICATE_EVENT")

    # ------------------------------------------------------------------
    # 3. Rate limits, network errors, corrupt archives, and budget caps
    # ------------------------------------------------------------------
    def test_03_rate_limits_retries_corrupt_files_and_budgets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)

            # 3a) Infinite retry config rejected
            cfg_inf = make_synthetic_config(max_retries=99)
            with self.assertRaises(CollectorError) as ctx_inf:
                run_preflight(write_config_file(tmp / "cfg_inf.json", cfg_inf))
            self.assertEqual(ctx_inf.exception.exit_code, EXIT_POLICY_REJECTED)

            # 3b) HTTP 429 succeeds within finite retries with Retry-After sleep
            srv_429_ok = SyntheticBinanceServer()
            srv_429_ok.register_month_all_streams("BTCUSDT", "2024-01")
            seen_429 = {"count": 0}

            def h429_once(url: str, _c: int):
                if "markPriceKlines" in url and seen_429["count"] < 2:
                    seen_429["count"] += 1
                    return HttpResponse(429, {"Retry-After": "1.5"}, b"Too Many Requests", url)
                return None

            srv_429_ok.override_handler = h429_once
            clk = FakeClock()
            cfg_p = write_config_file(tmp / "cfg_r.json", make_synthetic_config(symbols=["BTCUSDT"], streams=["mark_1h"], max_retries=2))
            code_ok, res_ok = run_collect(cfg_p, tmp / "out_429_ok", transport=srv_429_ok, clock_fn=clk.clock, sleep_fn=clk.sleep)
            self.assertEqual(code_ok, EXIT_COMPLETE)
            self.assertEqual(res_ok["budget_consumption"]["this_session"]["retry_count"], 2)
            self.assertEqual(clk.sleeps, [1.5, 1.5])

            # 3c) HTTP 429 exhausting max_retries -> FAILED exit 4 (no infinite retry)
            srv_429_fail = SyntheticBinanceServer()
            srv_429_fail.register_month_all_streams("BTCUSDT", "2024-01")
            srv_429_fail.override_handler = lambda u, _c: HttpResponse(429, {"Retry-After": "1"}, b"rate limit", u) if "markPriceKlines" in u else None
            clk2 = FakeClock()
            code_f, res_f = run_collect(cfg_p, tmp / "out_429_fail", transport=srv_429_fail, clock_fn=clk2.clock, sleep_fn=clk2.sleep)
            self.assertEqual(code_f, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res_f["error"]["code"], "FAILED_RATE_LIMIT_EXHAUSTED")
            self.assertEqual(len(clk2.sleeps), 2)

            # 3d) HTTP 418 IP ban -> immediate abort with 0 retries
            srv_418 = SyntheticBinanceServer()
            srv_418.override_handler = lambda u, _c: HttpResponse(418, {}, b"IP Banned", u) if "fundingInfo" in u else None
            clk3 = FakeClock()
            code_418, res_418 = run_collect(cfg_p, tmp / "out_418", transport=srv_418, clock_fn=clk3.clock, sleep_fn=clk3.sleep)
            self.assertEqual(code_418, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res_418["error"]["code"], "FAILED_IP_BAN_418")
            self.assertEqual(clk3.sleeps, [])

            # 3e) Corrupt ZIP, path traversal ZIP, zip-bomb (bounded extraction) & invalid OHLC
            srv_bad = SyntheticBinanceServer()
            bad_zip = b"NOT_A_ZIP_ARCHIVE"
            bad_cs = f"{hashlib.sha256(bad_zip).hexdigest()}  BTCUSDT-1h-2024-01.zip\n".encode("utf-8")
            srv_bad.vision_archives[("markPriceKlines", "BTCUSDT", "2024-01")] = (bad_zip, bad_cs)
            code_bz, res_bz = run_collect(cfg_p, tmp / "out_badzip", transport=srv_bad)
            self.assertEqual(code_bz, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res_bz["error"]["code"], "FAILED_BAD_ZIP_ARCHIVE")

            zbuf = io.BytesIO()
            with zipfile.ZipFile(zbuf, "w") as zf:
                zf.writestr("../evil.csv", "data")
            tz_bytes = zbuf.getvalue()
            tz_cs = f"{hashlib.sha256(tz_bytes).hexdigest()}  BTCUSDT-1h-2024-01.zip\n".encode("utf-8")
            srv_bad.vision_archives[("markPriceKlines", "BTCUSDT", "2024-01")] = (tz_bytes, tz_cs)
            code_tz, res_tz = run_collect(cfg_p, tmp / "out_travzip", transport=srv_bad)
            self.assertEqual(code_tz, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res_tz["error"]["code"], "FAILED_UNSAFE_ARCHIVE_MEMBER")

            zbomb_buf = io.BytesIO()
            with zipfile.ZipFile(zbomb_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("BTCUSDT-1h-2024-01.csv", "0," * 100_000)
            zbomb_bytes = zbomb_buf.getvalue()
            zbomb_cs = f"{hashlib.sha256(zbomb_bytes).hexdigest()}  BTCUSDT-1h-2024-01.zip\n".encode("utf-8")
            srv_bomb = SyntheticBinanceServer()
            srv_bomb.vision_archives[("markPriceKlines", "BTCUSDT", "2024-01")] = (zbomb_bytes, zbomb_cs)
            cfg_bomb = write_config_file(
                tmp / "cfg_bomb.json",
                make_synthetic_config(
                    symbols=["BTCUSDT"],
                    streams=["mark_1h"],
                    max_single_uncompressed_bytes=4096,
                    max_total_storage_bytes=10_000_000,
                ),
            )
            code_zb, res_zb = run_collect(cfg_bomb, tmp / "out_zbomb", transport=srv_bomb)
            self.assertEqual(code_zb, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res_zb["error"]["code"], "FAILED_UNCOMPRESSED_SIZE_LIMIT_EXCEEDED")

            zb_ohlc, cs_ohlc = build_kline_zip_and_checksum("BTCUSDT", "1h", "2024-01", corrupt_ohlc_at=5)
            srv_bad.vision_archives[("markPriceKlines", "BTCUSDT", "2024-01")] = (zb_ohlc, cs_ohlc)
            code_oh, res_oh = run_collect(cfg_p, tmp / "out_badohlc", transport=srv_bad)
            self.assertEqual(code_oh, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res_oh["error"]["code"], "FAILED_INVALID_OHLC_ENVELOPE")

            # 3f) Budget caps: max_http_requests, max_total_storage_bytes, & max_wall_time_seconds
            cfg_tiny_http = write_config_file(tmp / "cfg_tiny_http.json", make_synthetic_config(symbols=["BTCUSDT"], streams=["mark_1h"], max_http_requests=3))
            srv_ok = SyntheticBinanceServer()
            srv_ok.register_month_all_streams("BTCUSDT", "2024-01")
            code_th, res_th = run_collect(cfg_tiny_http, tmp / "out_tiny_http", transport=srv_ok)
            self.assertEqual(code_th, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res_th["error"]["code"], "FAILED_HTTP_BUDGET_EXHAUSTED")

            cfg_tiny_disk = write_config_file(
                tmp / "cfg_tiny_disk.json",
                make_synthetic_config(symbols=["BTCUSDT"], streams=["mark_1h"], max_single_uncompressed_bytes=4096, max_total_storage_bytes=4096),
            )
            code_td, res_td = run_collect(cfg_tiny_disk, tmp / "out_tiny_disk", transport=srv_ok)
            self.assertEqual(code_td, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertIn(res_td["error"]["code"], {"FAILED_UNCOMPRESSED_SIZE_LIMIT_EXCEEDED", "FAILED_STORAGE_BUDGET_EXCEEDED"})

            clk_wt = FakeClock(initial=100.0)
            srv_wt = SyntheticBinanceServer()
            srv_wt.register_month_all_streams("BTCUSDT", "2024-01")

            def advance_on_vision(url: str, c: float, r: float, m: int, h: tuple) -> HttpResponse:
                if "data.binance.vision" in url:
                    clk_wt.now += 0.7
                return srv_wt(url, c, r, m, h)

            cfg_wt = write_config_file(
                tmp / "cfg_wall_time.json",
                make_synthetic_config(symbols=["BTCUSDT"], streams=["mark_1h"], max_wall_time_seconds=1.0),
            )
            code_wt, res_wt = run_collect(cfg_wt, tmp / "out_wt", transport=advance_on_vision, clock_fn=clk_wt.clock, sleep_fn=clk_wt.sleep)
            self.assertEqual(code_wt, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res_wt["error"]["code"], "FAILED_TIME_BUDGET_EXCEEDED")
            m_wt = json.loads((tmp / "out_wt" / "manifest.json").read_bytes().decode("utf-8"))
            self.assertEqual(m_wt["units"][0]["status"], "FAILED_BUDGET_EXCEEDED")

    # ------------------------------------------------------------------
    # 4. Interrupt, resume without duplicate download, raw immutability
    # ------------------------------------------------------------------
    def test_04_interrupt_resume_no_duplicate_and_raw_immutability(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            srv = SyntheticBinanceServer()
            srv.register_month_all_streams("BTCUSDT", "2024-01")
            srv.register_month_all_streams("ETHUSDT", "2024-01")

            def fail_on_eth(url: str, _call: int) -> None:
                if "ETHUSDT" in url and ".zip" in url and not url.endswith(".CHECKSUM"):
                    raise CollectorError("FAILED_HTTP_TRANSPORT", "Simulated connection reset", EXIT_RUNTIME_OR_INTEGRITY_ERROR)

            srv.exception_handler = fail_on_eth
            cfg_p = write_config_file(
                tmp / "cfg_resume.json",
                make_synthetic_config(symbols=["BTCUSDT", "ETHUSDT"], streams=["mark_1h"], max_retries=0),
            )
            out_dir = tmp / "out_resume"
            code1, res1 = run_collect(cfg_p, out_dir, transport=srv)
            self.assertEqual(code1, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res1["status"], "FAILED")
            self.assertEqual(res1["unit_status_counts"]["verified_complete"], 1)

            btc_zip = out_dir / "raw" / "mark_1h" / "BTCUSDT" / "2024-01" / "BTCUSDT-1h-2024-01.zip"
            btc_cs = out_dir / "raw" / "mark_1h" / "BTCUSDT" / "2024-01" / "BTCUSDT-1h-2024-01.zip.CHECKSUM"
            btc_zip_sha_before, btc_zip_sz_before = sha256_file_from_disk(btc_zip)
            btc_cs_sha_before, _ = sha256_file_from_disk(btc_cs)

            srv.exception_handler = None
            srv.requests_seen.clear()
            code2, res2 = run_collect(cfg_p, out_dir, resume=True, transport=srv)
            self.assertEqual(code2, EXIT_COMPLETE)
            self.assertEqual(res2["status"], "COMPLETE")
            self.assertEqual(res2["budget_consumption"]["this_session"]["reused_verified_units"], 1)
            self.assertFalse(any("BTCUSDT" in u for u in srv.requests_seen))
            self.assertFalse(any("exchangeInfo" in u for u in srv.requests_seen))
            self.assertEqual(len(srv.requests_seen), 2)

            btc_zip_sha_after, btc_zip_sz_after = sha256_file_from_disk(btc_zip)
            btc_cs_sha_after, _ = sha256_file_from_disk(btc_cs)
            self.assertEqual((btc_zip_sha_before, btc_zip_sz_before), (btc_zip_sha_after, btc_zip_sz_after))
            self.assertEqual(btc_cs_sha_before, btc_cs_sha_after)

            v_code, v_res = run_verify(out_dir, require_complete=True)
            self.assertEqual(v_code, EXIT_COMPLETE)
            self.assertEqual(v_res["status"], "VERIFY_PASS")

            orig_bytes = btc_zip.read_bytes()
            btc_zip.write_bytes(orig_bytes[:-1] + bytes([orig_bytes[-1] ^ 0xFF]))
            with self.assertRaises(CollectorError) as ctx_tamper:
                run_collect(cfg_p, out_dir, resume=True, transport=srv)
            self.assertEqual(ctx_tamper.exception.code, "FAILED_EXISTING_ARTIFACT_CHECKSUM_MISMATCH")

    # ------------------------------------------------------------------
    # 5. Date, leap-year, ms vs us/s timestamp unit checks, & pre-listing
    # ------------------------------------------------------------------
    def test_05_dates_ms_vs_us_units_and_pre_listing_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)

            for bad_m in ("2023-13", "2024-00", "2023-02-29", "2024/01"):
                cfg_bm = write_config_file(tmp / f"cfg_{bad_m.replace('/', '_')}.json", make_synthetic_config(start_month=bad_m, end_month=bad_m))
                with self.assertRaises(CollectorError) as ctx_bm:
                    run_preflight(cfg_bm)
                self.assertEqual(ctx_bm.exception.exit_code, EXIT_POLICY_REJECTED)

            srv_leap = SyntheticBinanceServer()
            srv_leap.register_month_all_streams("BTCUSDT", "2023-02")
            srv_leap.register_month_all_streams("BTCUSDT", "2024-02")
            cfg_23 = write_config_file(tmp / "cfg_2302.json", make_synthetic_config(symbols=["BTCUSDT"], streams=["mark_1h"], start_month="2023-02", end_month="2023-02"))
            cfg_24 = write_config_file(tmp / "cfg_2402.json", make_synthetic_config(symbols=["BTCUSDT"], streams=["mark_1h"], start_month="2024-02", end_month="2024-02"))
            self.assertEqual(run_collect(cfg_23, tmp / "out_2302", transport=srv_leap)[0], EXIT_COMPLETE)
            self.assertEqual(run_collect(cfg_24, tmp / "out_2402", transport=srv_leap)[0], EXIT_COMPLETE)
            m23 = json.loads((tmp / "out_2302" / "manifest.json").read_bytes().decode("utf-8"))
            m24 = json.loads((tmp / "out_2402" / "manifest.json").read_bytes().decode("utf-8"))
            self.assertEqual(m23["units"][0]["row_count"], 672)
            self.assertEqual(m24["units"][0]["row_count"], 696)

            for mult, div, tag in [(1000, 1, "us"), (1, 1000, "s")]:
                zb_u, cs_u = build_kline_zip_and_checksum("BTCUSDT", "1h", "2024-01", ts_multiplier=mult, ts_divisor=div)
                srv_u = SyntheticBinanceServer()
                srv_u.vision_archives[("markPriceKlines", "BTCUSDT", "2024-01")] = (zb_u, cs_u)
                cfg_u = write_config_file(tmp / f"cfg_u_{tag}.json", make_synthetic_config(symbols=["BTCUSDT"], streams=["mark_1h"]))
                code_u, res_u = run_collect(cfg_u, tmp / f"out_u_{tag}", transport=srv_u)
                self.assertEqual(code_u, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
                self.assertEqual(res_u["error"]["code"], "FAILED_TIMESTAMP_UNIT_MISMATCH")
                self.assertIn(f"detected unit='{tag}'", res_u["error"]["message"])

                evs_u = build_funding_events_for_month("BTCUSDT", "2024-01", ts_multiplier=mult, ts_divisor=div)
                srv_fu = SyntheticBinanceServer()
                srv_fu.funding_events[("BTCUSDT", "2024-01")] = evs_u
                cfg_fu = write_config_file(tmp / f"cfg_fu_{tag}.json", make_synthetic_config(symbols=["BTCUSDT"], streams=["funding_settlement"]))
                code_fu, res_fu = run_collect(cfg_fu, tmp / f"out_fu_{tag}", transport=srv_fu)
                self.assertEqual(code_fu, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
                self.assertEqual(res_fu["error"]["code"], "FAILED_TIMESTAMP_UNIT_MISMATCH")

            mid_onboard_ms = parse_iso_utc_to_ms("2021-02-15T12:00:00Z")
            srv_pre = SyntheticBinanceServer(onboard_dates_ms={"SOLUSDT": mid_onboard_ms})
            srv_pre.register_month_all_streams("SOLUSDT", "2021-02")
            srv_pre.requests_seen.clear()
            cfg_pre = write_config_file(
                tmp / "cfg_pre.json",
                make_synthetic_config(symbols=["SOLUSDT"], streams=["mark_1h", "funding_settlement"], start_month="2021-01", end_month="2021-02"),
            )
            code_pre, res_pre = run_collect(cfg_pre, tmp / "out_pre", transport=srv_pre)
            self.assertEqual(code_pre, EXIT_COMPLETE)
            self.assertEqual(res_pre["unit_status_counts"]["skipped_pre_listing"], 2)
            self.assertFalse(any("2021-01" in u for u in srv_pre.requests_seen))
            m_pre = json.loads((tmp / "out_pre" / "manifest.json").read_bytes().decode("utf-8"))
            self.assertEqual(
                m_pre["stream_summaries"]["SOLUSDT"]["streams"]["mark_1h"]["first_available_utc"],
                "2021-02-15T12:00:00Z",
            )

    # ------------------------------------------------------------------
    # 6. Checksum mismatch detection (download & post-write verification)
    # ------------------------------------------------------------------
    def test_06_checksum_mismatch_detection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            srv = SyntheticBinanceServer()
            zb, _cs = build_kline_zip_and_checksum("BTCUSDT", "1h", "2024-01")
            wrong_cs = f"{'0' * 64}  BTCUSDT-1h-2024-01.zip\n".encode("utf-8")
            srv.vision_archives[("markPriceKlines", "BTCUSDT", "2024-01")] = (zb, wrong_cs)
            cfg_p = write_config_file(tmp / "cfg_cs.json", make_synthetic_config(symbols=["BTCUSDT"], streams=["mark_1h"]))
            code, res = run_collect(cfg_p, tmp / "out_cs_fail", transport=srv)
            self.assertEqual(code, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res["error"]["code"], "FAILED_ARCHIVE_CHECKSUM_MISMATCH")

            srv_ok = SyntheticBinanceServer()
            srv_ok.register_month_all_streams("BTCUSDT", "2024-01")
            out_ok = tmp / "out_cs_ok"
            self.assertEqual(run_collect(cfg_p, out_ok, transport=srv_ok)[0], EXIT_COMPLETE)
            csv_path = out_ok / "refined" / "merged" / "BTCUSDT_mark_1h.csv"
            raw_b = csv_path.read_bytes()
            csv_path.write_bytes(raw_b[:-2] + b"9\n")
            with self.assertRaises(CollectorError) as ctx_ver:
                run_verify(out_ok, require_complete=True)
            self.assertEqual(ctx_ver.exception.code, "FAILED_CHECKSUM_VERIFICATION")

    # ------------------------------------------------------------------
    # 7. Missing funding settlement mark price -> INCOMPLETE verdict
    # ------------------------------------------------------------------
    def test_07_missing_funding_settlement_mark_price_marks_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            for label, kw in [
                ("absent", {"missing_mark_indices": {4}}),
                ("empty", {"empty_mark_indices": {5}}),
                ("null", {"null_mark_indices": {6}}),
                ("zero", {"zero_mark_indices": {7}}),
            ]:
                srv = SyntheticBinanceServer()
                srv.register_month_all_streams("BTCUSDT", "2024-01")
                srv.funding_events[("BTCUSDT", "2024-01")] = build_funding_events_for_month("BTCUSDT", "2024-01", **kw)
                cfg_p = write_config_file(
                    tmp / f"cfg_mp_{label}.json",
                    make_synthetic_config(symbols=["BTCUSDT"], streams=["mark_1h", "funding_settlement"]),
                )
                out_dir = tmp / f"out_mp_{label}"
                code, res = run_collect(cfg_p, out_dir, transport=srv)
                self.assertEqual(code, EXIT_INCOMPLETE_DATA, label)
                self.assertEqual(res["status"], "INCOMPLETE", label)

                manifest = json.loads((out_dir / "manifest.json").read_bytes().decode("utf-8"))
                funding_units = [u for u in manifest["units"] if u["stream"] == "funding_settlement"]
                self.assertEqual(len(funding_units), 1)
                fu = funding_units[0]
                self.assertEqual(fu["status"], "INCOMPLETE_MISSING_SETTLEMENT_MARK_PRICE")
                self.assertEqual(fu["missing_settlement_mark_price_count"], 1)
                self.assertIsNone(fu["refined_artifact"])
                self.assertTrue(len(fu["raw_artifacts"]) == 1)
                self.assertFalse((out_dir / "refined" / "merged" / "BTCUSDT_funding_settlement.csv").exists())

                self.assertEqual(run_verify(out_dir, require_complete=False)[0], EXIT_COMPLETE)
                v_code, _ = run_verify(out_dir, require_complete=True)
                self.assertEqual(v_code, EXIT_INCOMPLETE_DATA)

    # ------------------------------------------------------------------
    # 8. Cross-platform paths, LF/CRLF disk-byte hashing, bundle & CLI preflight
    # ------------------------------------------------------------------
    def test_08_cross_platform_paths_crlf_disk_hash_export_and_cli(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            srv = SyntheticBinanceServer()
            for sym in ("BTCUSDT", "ETHUSDT"):
                srv.register_month_all_streams(sym, "2024-01")
            cfg_p = write_config_file(
                tmp / "cfg_full.json",
                make_synthetic_config(symbols=["BTCUSDT", "ETHUSDT"], streams=["exec_15m", "mark_1h", "funding_settlement"]),
            )
            out_dir = tmp / "out_bundle"
            code, res = run_collect(cfg_p, out_dir, transport=srv)
            self.assertEqual(code, EXIT_COMPLETE)
            self.assertEqual(res["status"], "COMPLETE")

            sums_bytes = (out_dir / "SHA256SUMS.txt").read_bytes()
            self.assertNotIn(b"\r", sums_bytes)
            sums_lines = [ln for ln in sums_bytes.decode("utf-8").splitlines() if ln.strip()]
            for line in sums_lines:
                digest, rel_posix = line.split("  ", 1)
                self.assertNotIn("\\", rel_posix)
                self.assertFalse(rel_posix.startswith("/"))
                disk_sha, _ = sha256_file_from_disk(out_dir / rel_posix)
                self.assertEqual(digest, disk_sha)

            merged_csv = out_dir / "refined" / "merged" / "BTCUSDT_exec_15m.csv"
            lf_bytes = merged_csv.read_bytes()
            self.assertNotIn(b"\r", lf_bytes)
            crlf_bytes = lf_bytes.replace(b"\n", b"\r\n")
            merged_csv.write_bytes(crlf_bytes)
            with self.assertRaises(CollectorError) as ctx_crlf:
                run_verify(out_dir, require_complete=True)
            self.assertEqual(ctx_crlf.exception.code, "FAILED_CHECKSUM_VERIFICATION")
            merged_csv.write_bytes(lf_bytes)
            self.assertEqual(run_verify(out_dir, require_complete=True)[0], EXIT_COMPLETE)

            sums_orig = (out_dir / "SHA256SUMS.txt").read_bytes()
            tampered_sums = sums_orig.decode("utf-8").replace("refined/merged/", "refined\\merged\\").encode("utf-8")
            (out_dir / "SHA256SUMS.txt").write_bytes(tampered_sums)
            with self.assertRaises(CollectorError) as ctx_bs:
                run_verify(out_dir)
            self.assertEqual(ctx_bs.exception.code, "FAILED_UNSAFE_RELATIVE_PATH")
            (out_dir / "SHA256SUMS.txt").write_bytes(sums_orig)

            tar_path = tmp / "export.tar.gz"
            exp_code, exp_res = run_export_bundle(out_dir, tar_path)
            self.assertEqual(exp_code, EXIT_COMPLETE)
            tar_disk_sha, _ = sha256_file_from_disk(tar_path)
            self.assertEqual(exp_res["archive_sha256"], tar_disk_sha)
            sidecar_text = Path(f"{tar_path}.sha256").read_bytes().decode("utf-8").strip()
            self.assertEqual(sidecar_text, f"{tar_disk_sha}  {tar_path.name}")

            extracted_dir = tmp / "extracted"
            extracted_dir.mkdir()
            with tarfile.open(tar_path, "r:gz") as tf:
                tf.extractall(extracted_dir, filter="data")
            self.assertEqual(run_verify(extracted_dir, require_complete=True)[0], EXIT_COMPLETE)

            pkg_root = self._package_root()
            for idx, cfg_rel in enumerate(
                [
                    "configs/preflight_check_example.json",
                    "configs/pilot_1m_5sym_2024_01.json",
                    "configs/full_pre2024_2021_01_to_2023_12.json",
                ]
            ):
                pre_out = tmp / f"pre_cli_{idx}"
                proc = subprocess.run(
                    [sys.executable, "-B", "-m", "collector", "preflight", "--config", cfg_rel, "--out-dir", str(pre_out)],
                    cwd=str(pkg_root),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr} stdout={proc.stdout}")
                payload = json.loads(proc.stdout)
                self.assertEqual(payload["status"], "PREFLIGHT_PASS")
                self.assertEqual(payload["network_requests_executed"], 0)

            # Public CLI main() MUST never report partial/incomplete or failed runs as exit 0 or COMPLETE
            srv_partial = SyntheticBinanceServer()
            srv_partial.register_month_all_streams("BTCUSDT", "2024-01")
            srv_partial.register_month_all_streams("ETHUSDT", "2024-01")
            srv_partial.funding_events[("ETHUSDT", "2024-01")] = build_funding_events_for_month(
                "ETHUSDT",
                "2024-01",
                missing_mark_indices={3},
            )
            out_cli_partial = tmp / "out_cli_partial"
            stdout_buf = io.StringIO()
            with contextlib.redirect_stdout(stdout_buf):
                cli_code = cli_main(
                    ["collect", "--config", str(cfg_p), "--out-dir", str(out_cli_partial)],
                    transport=srv_partial,
                )
            self.assertEqual(cli_code, EXIT_INCOMPLETE_DATA)
            cli_payload = json.loads(stdout_buf.getvalue())
            self.assertEqual(cli_payload["status"], "INCOMPLETE")
            self.assertEqual(cli_payload["exit_code"], EXIT_INCOMPLETE_DATA)

            ver_buf = io.StringIO()
            with contextlib.redirect_stdout(ver_buf):
                cli_ver_code = cli_main(["verify", "--package-dir", str(out_cli_partial), "--require-complete"])
            self.assertEqual(cli_ver_code, EXIT_INCOMPLETE_DATA)

            exp_buf = io.StringIO()
            with contextlib.redirect_stdout(exp_buf):
                cli_exp_code = cli_main(
                    [
                        "export-bundle",
                        "--package-dir",
                        str(out_cli_partial),
                        "--archive-path",
                        str(tmp / "blocked_incomplete.tar.gz"),
                    ]
                )
            self.assertEqual(cli_exp_code, EXIT_INCOMPLETE_DATA)
            self.assertFalse((tmp / "blocked_incomplete.tar.gz").exists())

            # Partial runtime failure via public CLI also returns non-zero FAILED (exit 4)
            srv_pfail = SyntheticBinanceServer()
            srv_pfail.register_month_all_streams("BTCUSDT", "2024-01")
            srv_pfail.override_handler = lambda u, _c: (
                HttpResponse(500, {}, b"err", u) if "ETHUSDT" in u else None
            )
            cfg_pfail = write_config_file(
                tmp / "cfg_pfail.json",
                make_synthetic_config(symbols=["BTCUSDT", "ETHUSDT"], streams=["mark_1h"], max_retries=0),
            )
            out_cli_fail = tmp / "out_cli_fail"
            fail_buf = io.StringIO()
            with contextlib.redirect_stdout(fail_buf):
                cli_fail_code = cli_main(
                    ["collect", "--config", str(cfg_pfail), "--out-dir", str(out_cli_fail)],
                    transport=srv_pfail,
                )
            self.assertEqual(cli_fail_code, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            cli_fail_payload = json.loads(fail_buf.getvalue())
            self.assertEqual(cli_fail_payload["status"], "FAILED")
            self.assertEqual(cli_fail_payload["exit_code"], EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(cli_fail_payload["unit_status_counts"]["verified_complete"], 1)
            self.assertEqual(cli_fail_payload["unit_status_counts"]["failed"], 1)

    # ------------------------------------------------------------------
    # 9. Retry-After non-reduction, HTTP-date, & malformed header fail-closed
    # ------------------------------------------------------------------
    def test_09_retry_after_non_reduction_http_date_and_invalid_values(self) -> None:
        fixed_now = _dt.datetime(2026, 11, 23, 0, 0, 0, tzinfo=_dt.timezone.utc)
        self.assertEqual(parse_retry_after_header("120", now_utc=fixed_now), 120.0)
        self.assertEqual(parse_retry_after_header("1.5", now_utc=fixed_now), 1.5)
        self.assertEqual(parse_retry_after_header("Mon, 23 Nov 2026 00:02:00 GMT", now_utc=fixed_now), 120.0)
        self.assertEqual(parse_retry_after_header("Sun, 22 Nov 2026 23:59:50 GMT", now_utc=fixed_now), 0.0)
        for bad_ra in ("", "   ", "-5", "+5", "NaN", "inf", "not-a-date", "Tue, 99 Nov 2026 00:00:00 GMT"):
            with self.assertRaises(CollectorError) as ctx_bad:
                parse_retry_after_header(bad_ra, now_utc=fixed_now)
            self.assertEqual(ctx_bad.exception.code, "FAILED_INVALID_RETRY_AFTER", f"raw={bad_ra!r}")

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)

            # 9a) Retry-After=120 with max_retry_after_seconds=60 -> abort with 0 early retries & 0 sleeps
            srv_120 = SyntheticBinanceServer()
            srv_120.register_month_all_streams("BTCUSDT", "2024-01")
            mark_calls_120: List[str] = []

            def h120(url: str, _c: int) -> Optional[HttpResponse]:
                if "markPriceKlines" in url:
                    mark_calls_120.append(url)
                    return HttpResponse(429, {"Retry-After": "120"}, b"slow down", url)
                return None

            srv_120.override_handler = h120
            clk_120 = FakeClock()
            cfg_120 = write_config_file(
                tmp / "cfg_ra120.json",
                make_synthetic_config(
                    symbols=["BTCUSDT"],
                    streams=["mark_1h"],
                    max_retries=2,
                    max_retry_after_seconds=60.0,
                    max_wall_time_seconds=300.0,
                ),
            )
            code_120, res_120 = run_collect(
                cfg_120,
                tmp / "out_ra120",
                transport=srv_120,
                clock_fn=clk_120.clock,
                sleep_fn=clk_120.sleep,
                utc_now_fn=lambda: fixed_now,
            )
            self.assertEqual(code_120, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res_120["error"]["code"], "FAILED_RETRY_AFTER_EXCEEDS_MAX_WAIT")
            self.assertEqual(len(mark_calls_120), 1)
            self.assertEqual(clk_120.sleeps, [])

            # 9b) Retry-After=45 <= max_retry_after(60) but > remaining wall time(20) -> 0 early retries
            srv_rem = SyntheticBinanceServer()
            srv_rem.register_month_all_streams("BTCUSDT", "2024-01")
            mark_calls_rem: List[str] = []

            def h45(url: str, _c: int) -> Optional[HttpResponse]:
                if "markPriceKlines" in url:
                    mark_calls_rem.append(url)
                    return HttpResponse(429, {"Retry-After": "45"}, b"wait", url)
                return None

            srv_rem.override_handler = h45
            clk_rem = FakeClock()
            cfg_rem = write_config_file(
                tmp / "cfg_rarem.json",
                make_synthetic_config(
                    symbols=["BTCUSDT"],
                    streams=["mark_1h"],
                    max_retries=2,
                    max_retry_after_seconds=60.0,
                    max_wall_time_seconds=20.0,
                ),
            )
            code_rem, res_rem = run_collect(
                cfg_rem,
                tmp / "out_rarem",
                transport=srv_rem,
                clock_fn=clk_rem.clock,
                sleep_fn=clk_rem.sleep,
                utc_now_fn=lambda: fixed_now,
            )
            self.assertEqual(code_rem, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res_rem["error"]["code"], "FAILED_RETRY_AFTER_EXCEEDS_REMAINING_TIME")
            self.assertEqual(len(mark_calls_rem), 1)
            self.assertEqual(clk_rem.sleeps, [])

            # 9c) HTTP-date +120s rejected with 0 retries; HTTP-date +3s sleeps full 3.0s and succeeds
            srv_hd_long = SyntheticBinanceServer()
            srv_hd_long.register_month_all_streams("BTCUSDT", "2024-01")
            hd_calls: List[str] = []

            def h_hd_long(url: str, _c: int) -> Optional[HttpResponse]:
                if "markPriceKlines" in url:
                    hd_calls.append(url)
                    return HttpResponse(429, {"Retry-After": "Mon, 23 Nov 2026 00:02:00 GMT"}, b"hd", url)
                return None

            srv_hd_long.override_handler = h_hd_long
            clk_hdl = FakeClock()
            code_hdl, res_hdl = run_collect(
                cfg_120,
                tmp / "out_hdl",
                transport=srv_hd_long,
                clock_fn=clk_hdl.clock,
                sleep_fn=clk_hdl.sleep,
                utc_now_fn=lambda: fixed_now,
            )
            self.assertEqual(code_hdl, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res_hdl["error"]["code"], "FAILED_RETRY_AFTER_EXCEEDS_MAX_WAIT")
            self.assertEqual(len(hd_calls), 1)
            self.assertEqual(clk_hdl.sleeps, [])

            srv_hd_ok = SyntheticBinanceServer()
            srv_hd_ok.register_month_all_streams("BTCUSDT", "2024-01")
            seen_hd = {"n": 0}

            def h_hd_ok(url: str, _c: int) -> Optional[HttpResponse]:
                if "markPriceKlines" in url and seen_hd["n"] == 0:
                    seen_hd["n"] += 1
                    return HttpResponse(429, {"Retry-After": "Mon, 23 Nov 2026 00:00:03 GMT"}, b"hd3", url)
                return None

            srv_hd_ok.override_handler = h_hd_ok
            clk_hdo = FakeClock()
            code_hdo, res_hdo = run_collect(
                cfg_120,
                tmp / "out_hdo",
                transport=srv_hd_ok,
                clock_fn=clk_hdo.clock,
                sleep_fn=clk_hdo.sleep,
                utc_now_fn=lambda: fixed_now,
            )
            self.assertEqual(code_hdo, EXIT_COMPLETE)
            self.assertEqual(clk_hdo.sleeps, [3.0])
            self.assertEqual(res_hdo["budget_consumption"]["this_session"]["retry_count"], 1)

            # 9d) Invalid Retry-After fails closed without sleeping/retrying
            for bad_val, tag in [("-5", "neg"), ("bogus-date", "malformed")]:
                srv_inv = SyntheticBinanceServer()
                srv_inv.register_month_all_streams("BTCUSDT", "2024-01")
                inv_calls: List[str] = []

                def h_inv(url: str, _c: int, *, _v: str = bad_val, _lc: List[str] = inv_calls) -> Optional[HttpResponse]:
                    if "markPriceKlines" in url:
                        _lc.append(url)
                        return HttpResponse(429, {"Retry-After": _v}, b"bad", url)
                    return None

                srv_inv.override_handler = h_inv
                clk_inv = FakeClock()
                code_inv, res_inv = run_collect(
                    cfg_120,
                    tmp / f"out_inv_{tag}",
                    transport=srv_inv,
                    clock_fn=clk_inv.clock,
                    sleep_fn=clk_inv.sleep,
                    utc_now_fn=lambda: fixed_now,
                )
                self.assertEqual(code_inv, EXIT_RUNTIME_OR_INTEGRITY_ERROR, tag)
                self.assertEqual(res_inv["error"]["code"], "FAILED_INVALID_RETRY_AFTER", tag)
                self.assertEqual(len(inv_calls), 1, tag)
                self.assertEqual(clk_inv.sleeps, [], tag)

    # ------------------------------------------------------------------
    # 10. Cumulative request & download byte budgets across resume & crashes
    # ------------------------------------------------------------------
    def test_10_cumulative_budgets_across_resume_and_abnormal_crash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            syms = ["BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT"]
            months = ["2024-01", "2024-02", "2024-03", "2024-04", "2024-05"]

            srv_1 = SyntheticBinanceServer()
            srv_2 = SyntheticBinanceServer()
            srv_3 = SyntheticBinanceServer()
            for sym in syms:
                for ym in months:
                    srv_1.register_month_all_streams(sym, ym)
                    srv_2.register_month_all_streams(sym, ym)
                    srv_3.register_month_all_streams(sym, ym)

            def crash_on_44th(url: str, call_num: int) -> None:
                del url
                if call_num == 44:
                    raise RuntimeError("Simulated uncaught process crash on call #44")

            srv_1.exception_handler = crash_on_44th
            cfg_req = write_config_file(
                tmp / "cfg_45.json",
                make_synthetic_config(
                    symbols=syms,
                    streams=["mark_1h"],
                    start_month="2024-01",
                    end_month="2024-05",
                    fetch_exchange_metadata=False,
                    max_retries=0,
                    max_http_requests=45,
                ),
            )
            out_req = tmp / "out_req_45"
            with self.assertRaises(RuntimeError):
                run_collect(cfg_req, out_req, transport=srv_1)

            cp1 = json.loads((out_req / "checkpoint.json").read_bytes().decode("utf-8"))
            self.assertEqual(cp1["cumulative_consumption"]["sessions"], 1)
            self.assertEqual(cp1["cumulative_consumption"]["http_requests_attempted"], 44)
            self.assertEqual(cp1["cumulative_consumption"]["last_session_status"], "ABORTED_ABNORMALLY")

            # Resume: 44/45 already consumed -> allows at most 1 additional HTTP call!
            code2, res2 = run_collect(cfg_req, out_req, resume=True, transport=srv_2)
            self.assertEqual(code2, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res2["error"]["code"], "FAILED_HTTP_BUDGET_EXHAUSTED")
            self.assertEqual(len(srv_2.requests_seen), 1)
            self.assertEqual(res2["budget_consumption"]["this_session"]["http_requests_attempted"], 1)
            self.assertEqual(res2["budget_consumption"]["cumulative"]["http_requests_attempted"], 45)
            self.assertEqual(res2["budget_consumption"]["cumulative"]["remaining_http_requests"], 0)
            self.assertEqual(res2["budget_consumption"]["cumulative"]["sessions"], 2)

            # Second resume: 45/45 exhausted -> 0 HTTP requests permitted
            code3, res3 = run_collect(cfg_req, out_req, resume=True, transport=srv_3)
            self.assertEqual(code3, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res3["error"]["code"], "FAILED_HTTP_BUDGET_EXHAUSTED")
            self.assertEqual(len(srv_3.requests_seen), 0)
            self.assertEqual(res3["budget_consumption"]["this_session"]["http_requests_attempted"], 0)
            self.assertEqual(res3["budget_consumption"]["cumulative"]["http_requests_attempted"], 45)

            # 10b) Download byte budget mostly consumed -> abnormal crash -> resume enforces cumulative ceiling
            zb_btc, cs_btc = srv_1.vision_archives[("markPriceKlines", "BTCUSDT", "2024-01")]
            btc_wire = len(cs_btc) + len(zb_btc)
            srv_b1 = SyntheticBinanceServer()
            srv_b2 = SyntheticBinanceServer()
            srv_b3 = SyntheticBinanceServer()
            for s in (srv_b1, srv_b2, srv_b3):
                s.register_month_all_streams("BTCUSDT", "2024-01")
                s.register_month_all_streams("ETHUSDT", "2024-01")

            def crash_after_btc(url: str, _call: int) -> None:
                if "ETHUSDT" in url:
                    raise RuntimeError("Simulated abrupt stop before ETHUSDT download")

            srv_b1.exception_handler = crash_after_btc
            cfg_bytes = write_config_file(
                tmp / "cfg_bytes.json",
                make_synthetic_config(
                    symbols=["BTCUSDT", "ETHUSDT"],
                    streams=["mark_1h"],
                    fetch_exchange_metadata=False,
                    max_retries=0,
                    max_compressed_download_bytes=btc_wire + 300,
                    max_single_response_bytes=btc_wire + 300,
                ),
            )
            out_bytes = tmp / "out_bytes"
            with self.assertRaises(RuntimeError):
                run_collect(cfg_bytes, out_bytes, transport=srv_b1)

            cp_b1 = json.loads((out_bytes / "checkpoint.json").read_bytes().decode("utf-8"))
            self.assertEqual(cp_b1["cumulative_consumption"]["compressed_bytes_downloaded"], btc_wire)
            self.assertEqual(cp_b1["cumulative_consumption"]["last_session_status"], "ABORTED_ABNORMALLY")

            # Resume: only 300 B remain; ETHUSDT checksum fits (~90 B), ETHUSDT zip (~4 KB) breaches cumulative ceiling
            code_b2, res_b2 = run_collect(cfg_bytes, out_bytes, resume=True, transport=srv_b2)
            self.assertEqual(code_b2, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res_b2["error"]["code"], "FAILED_DOWNLOAD_BYTE_BUDGET_EXHAUSTED")
            self.assertEqual(res_b2["budget_consumption"]["this_session"]["compressed_bytes_downloaded"], sum(
                len(srv_b2.vision_archives[("markPriceKlines", "ETHUSDT", "2024-01")][i]) for i in (1, 0)
            ))
            self.assertGreater(res_b2["budget_consumption"]["cumulative"]["compressed_bytes_downloaded"], btc_wire)
            self.assertEqual(res_b2["budget_consumption"]["cumulative"]["remaining_compressed_download_bytes"], 0)

            # Subsequent resume sees 0 remaining download bytes and makes 0 HTTP requests
            code_b3, _res_b3 = run_collect(cfg_bytes, out_bytes, resume=True, transport=srv_b3)
            self.assertEqual(code_b3, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(len(srv_b3.requests_seen), 0)

            # Tampered checkpoint cumulative_consumption (< raw bytes on disk) rejected before HTTP calls
            cp_tampered = json.loads((out_bytes / "checkpoint.json").read_bytes().decode("utf-8"))
            cp_tampered["cumulative_consumption"]["compressed_bytes_downloaded"] = 0
            (out_bytes / "checkpoint.json").write_bytes((json.dumps(cp_tampered, indent=2) + "\n").encode("utf-8"))
            with self.assertRaises(CollectorError) as ctx_tamp:
                run_collect(cfg_bytes, out_bytes, resume=True, transport=srv_b3)
            self.assertEqual(ctx_tamp.exception.code, "FAILED_CORRUPT_CHECKPOINT")
            self.assertEqual(len(srv_b3.requests_seen), 0)

    # ------------------------------------------------------------------
    # 11. Redirect rejection & exact byte/request accounting across stdlib/mock
    # ------------------------------------------------------------------
    def test_11_redirect_rejection_and_byte_request_accounting(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            target_url = "https://data.binance.vision/data/futures/um/monthly/markPriceKlines/BTCUSDT/1h/BTCUSDT-1h-2024-01.zip"
            redirect_body = b"Redirect body 123"
            open_calls: List[str] = []

            class Fake302HTTPSHandler(urllib.request.HTTPSHandler):
                def https_open(self, req: urllib.request.Request) -> Any:
                    open_calls.append(req.full_url)
                    hdrs = HTTPMessage()
                    hdrs["Location"] = (
                        "https://data.binance.vision/data/futures/um/monthly/markPriceKlines/BTCUSDT/1h/BTCUSDT-1h-2024-02.zip"
                    )
                    resp = addinfourl(io.BytesIO(redirect_body), hdrs, req.full_url, code=302)
                    resp.msg = "Found"
                    return resp

            cfg_p = write_config_file(
                tmp / "cfg_redir_unit.json",
                make_synthetic_config(symbols=["BTCUSDT"], streams=["mark_1h"], fetch_exchange_metadata=False),
            )
            cfg = load_and_validate_config(cfg_p)
            tracker = BudgetTracker()
            stdlib_t = build_stdlib_https_transport(
                lambda u: validate_request_url(
                    u,
                    allowed_hosts=cfg.allowed_hosts,
                    allowed_symbols=cfg.allowed_symbols,
                    allowed_start_ms=cfg.allowed_start_ms,
                    oos_forbidden_start_ms=cfg.oos_forbidden_start_ms,
                ),
                opener_factory=lambda _c, _r, _ctx, _d: urllib.request.build_opener(
                    _NoRedirectHandler(),
                    Fake302HTTPSHandler(),
                ),
            )
            client = RateLimitedClient(cfg, transport=stdlib_t, tracker=tracker)
            with self.assertRaises(CollectorError) as ctx_r:
                client.get(target_url)
            self.assertEqual(ctx_r.exception.code, "BLOCKED_HTTP_REDIRECT")
            self.assertEqual(ctx_r.exception.exit_code, EXIT_POLICY_REJECTED)
            self.assertEqual(len(open_calls), 1)
            self.assertEqual(tracker.http_requests_attempted, 1)
            self.assertEqual(tracker.compressed_bytes_downloaded, len(redirect_body))
            self.assertEqual(tracker.status_code_counts, {"302": 1})

            # Mock 301 redirect and silent same-host 200 final_url redirect in run_collect
            for label, resp_fn in [
                ("status_301", lambda u: HttpResponse(301, {"Location": u.replace("2024-01", "2024-02")}, b"301-payload-bytes", u)),
                ("silent_200_final_url", lambda u: HttpResponse(200, {}, b"200-silent-redir-bytes", u + ".CHECKSUM" if not u.endswith(".CHECKSUM") else u[:-9])),
            ]:
                expected_bytes = 17 if label == "status_301" else 22
                srv_r = SyntheticBinanceServer()
                srv_r.override_handler = lambda u, _c, _fn=resp_fn: _fn(u)
                code_r, res_r = run_collect(cfg_p, tmp / f"out_{label}", transport=srv_r)
                self.assertEqual(code_r, EXIT_POLICY_REJECTED, label)
                self.assertEqual(res_r["error"]["code"], "BLOCKED_HTTP_REDIRECT", label)
                self.assertEqual(res_r["budget_consumption"]["this_session"]["http_requests_attempted"], 1, label)
                self.assertEqual(res_r["budget_consumption"]["this_session"]["compressed_bytes_downloaded"], expected_bytes, label)

    # ------------------------------------------------------------------
    # 12. Overall wall-time deadline on slow chunks & failed response bytes
    # ------------------------------------------------------------------
    def test_12_overall_deadline_slow_chunks_and_failed_response_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            clk = FakeClock(initial=500.0)
            requested_timeouts: List[Optional[float]] = []

            class SlowChunkResponse:
                def __init__(self, final_url: str) -> None:
                    self._url = final_url
                    self._chunks = [b"A" * 120, b"B" * 120, b"C" * 120]
                    self._idx = 0
                    self.status = 200
                    self.headers = {"content-type": "application/octet-stream"}
                    self.last_timeout: Optional[float] = None

                def geturl(self) -> str:
                    return self._url

                def settimeout(self, timeout_val: float) -> None:
                    self.last_timeout = timeout_val

                def read(self, _n: int = -1) -> bytes:
                    requested_timeouts.append(self.last_timeout)
                    clk.now += 0.6
                    if self._idx >= len(self._chunks):
                        return b""
                    out = self._chunks[self._idx]
                    self._idx += 1
                    return out

                def __enter__(self) -> SlowChunkResponse:
                    return self

                def __exit__(self, *_args: object) -> None:
                    return None

            class SlowChunkOpener:
                def open(self, req: urllib.request.Request) -> SlowChunkResponse:
                    return SlowChunkResponse(req.full_url)

            cfg_p = write_config_file(
                tmp / "cfg_slow_chunk.json",
                make_synthetic_config(
                    symbols=["BTCUSDT"],
                    streams=["mark_1h"],
                    fetch_exchange_metadata=False,
                    max_retries=0,
                    max_wall_time_seconds=1.0,
                ),
            )
            cfg = load_and_validate_config(cfg_p)

            # Use a holder so transport queries remaining_wall_fn dynamically against clk
            rem_wall_fn = lambda: max(0.0, cfg.max_wall_time_seconds - max(0.0, clk.clock() - 500.0))
            slow_transport = build_stdlib_https_transport(
                lambda u: validate_request_url(
                    u,
                    allowed_hosts=cfg.allowed_hosts,
                    allowed_symbols=cfg.allowed_symbols,
                    allowed_start_ms=cfg.allowed_start_ms,
                    oos_forbidden_start_ms=cfg.oos_forbidden_start_ms,
                ),
                clock_fn=clk.clock,
                remaining_wall_fn=rem_wall_fn,
                opener_factory=lambda _c, _r, _ctx, _d: SlowChunkOpener(),  # type: ignore[return-value, arg-type]
            )
            code_sc, res_sc = run_collect(
                cfg_p,
                tmp / "out_slow_chunk",
                transport=slow_transport,
                clock_fn=clk.clock,
                sleep_fn=clk.sleep,
            )
            self.assertEqual(code_sc, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res_sc["error"]["code"], "FAILED_TIME_BUDGET_EXCEEDED")
            # Chunk 1 read (+0.6s -> 0.4s left), Chunk 2 read (+0.6s -> 1.2s > 1.0s), Chunk 3 never read
            self.assertEqual(len(requested_timeouts), 2)
            self.assertAlmostEqual(float(requested_timeouts[0]), 1.0, places=5)
            self.assertAlmostEqual(float(requested_timeouts[1]), 0.4, places=5)
            self.assertEqual(res_sc["budget_consumption"]["this_session"]["compressed_bytes_downloaded"], 240)
            self.assertEqual(res_sc["budget_consumption"]["cumulative"]["compressed_bytes_downloaded"], 240)
            self.assertGreaterEqual(res_sc["budget_consumption"]["this_session"]["elapsed_wall_seconds"], 1.19)

            # 12b) Failed transport with partial bytes_received=350 + retry HTTP 500 with 200-byte body
            clk2 = FakeClock(initial=100.0)
            attempt_n = {"i": 0}

            def fail_partial_then_500(
                url: str,
                _c: float,
                _r: float,
                _m: int,
                _h: tuple,
            ) -> HttpResponse:
                attempt_n["i"] += 1
                if attempt_n["i"] == 1:
                    clk2.now += 0.3
                    raise CollectorError(
                        "FAILED_HTTP_TRANSPORT",
                        "Simulated mid-stream reset after 350 bytes",
                        EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                        bytes_received=350,
                    )
                clk2.now += 0.1
                return HttpResponse(500, {}, b"E" * 200, url)

            cfg_p2 = write_config_file(
                tmp / "cfg_partial_err.json",
                make_synthetic_config(
                    symbols=["BTCUSDT"],
                    streams=["mark_1h"],
                    fetch_exchange_metadata=False,
                    max_retries=1,
                    retry_backoff_base_seconds=0.25,
                ),
            )
            code_pe, res_pe = run_collect(
                cfg_p2,
                tmp / "out_partial_err",
                transport=fail_partial_then_500,
                clock_fn=clk2.clock,
                sleep_fn=clk2.sleep,
            )
            self.assertEqual(code_pe, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res_pe["error"]["code"], "FAILED_SERVER_ERROR_EXHAUSTED")
            self.assertEqual(res_pe["budget_consumption"]["this_session"]["http_requests_attempted"], 2)
            self.assertEqual(res_pe["budget_consumption"]["this_session"]["retry_count"], 1)
            self.assertEqual(res_pe["budget_consumption"]["this_session"]["compressed_bytes_downloaded"], 550)
            self.assertEqual(res_pe["budget_consumption"]["cumulative"]["compressed_bytes_downloaded"], 550)
            self.assertGreaterEqual(res_pe["budget_consumption"]["this_session"]["elapsed_wall_seconds"], 0.64)

    # ------------------------------------------------------------------
    # 13. Exchange 1m weight limit: abort or verified minute-window recovery
    # ------------------------------------------------------------------
    def test_13_exchange_weight_limit_abort_and_verifiable_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)

            # 13a) Weight limit hit at :05s of minute -> 56.0s reset > max_retry_after_seconds(30.0) -> abort, 0 follow-up calls
            srv_abort = SyntheticBinanceServer()
            srv_abort.register_month_all_streams("BTCUSDT", "2024-01")

            def h_weight_early_min(url: str, _c: int) -> Optional[HttpResponse]:
                if "/fapi/v1/exchangeInfo" in url:
                    payload = {"symbols": [{"symbol": "BTCUSDT", "status": "TRADING", "onboardDate": 1577836800000}]}
                    return HttpResponse(
                        200,
                        {"x-mbx-used-weight-1m": "2000", "Date": "Mon, 23 Nov 2026 00:00:05 GMT"},
                        json.dumps(payload).encode("utf-8"),
                        url,
                    )
                return None

            srv_abort.override_handler = h_weight_early_min
            clk_a = FakeClock()
            cfg_abort = write_config_file(
                tmp / "cfg_w_abort.json",
                make_synthetic_config(
                    symbols=["BTCUSDT"],
                    streams=["mark_1h"],
                    max_used_weight_1m=2000,
                    max_retry_after_seconds=30.0,
                    max_wall_time_seconds=300.0,
                ),
            )
            code_a, res_a = run_collect(cfg_abort, tmp / "out_w_abort", transport=srv_abort, clock_fn=clk_a.clock, sleep_fn=clk_a.sleep)
            self.assertEqual(code_a, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res_a["error"]["code"], "FAILED_EXCHANGE_WEIGHT_LIMIT_REACHED")
            self.assertEqual(len(srv_abort.requests_seen), 1)
            self.assertEqual(clk_a.sleeps, [])

            # 13b) Weight limit hit at :40s -> waits full 21.0s minute rollover (NOT 1s!) and succeeds when weight drops
            srv_rec = SyntheticBinanceServer()
            srv_rec.register_month_all_streams("BTCUSDT", "2024-01")

            def h_weight_40s(url: str, _c: int) -> Optional[HttpResponse]:
                if "/fapi/v1/exchangeInfo" in url:
                    payload = {"symbols": [{"symbol": "BTCUSDT", "status": "TRADING", "onboardDate": 1577836800000}]}
                    return HttpResponse(
                        200,
                        {"x-mbx-used-weight-1m": "2000", "Date": "Mon, 23 Nov 2026 00:00:40 GMT"},
                        json.dumps(payload).encode("utf-8"),
                        url,
                    )
                if "/fapi/v1/fundingInfo" in url:
                    return HttpResponse(200, {"x-mbx-used-weight-1m": "1"}, b"[]", url)
                return None

            srv_rec.override_handler = h_weight_40s
            clk_r = FakeClock()
            cfg_rec = write_config_file(
                tmp / "cfg_w_rec.json",
                make_synthetic_config(
                    symbols=["BTCUSDT"],
                    streams=["mark_1h"],
                    max_used_weight_1m=2000,
                    max_retry_after_seconds=65.0,
                    max_wall_time_seconds=300.0,
                ),
            )
            code_r, res_r = run_collect(cfg_rec, tmp / "out_w_rec", transport=srv_rec, clock_fn=clk_r.clock, sleep_fn=clk_r.sleep)
            self.assertEqual(code_r, EXIT_COMPLETE)
            self.assertEqual(len(clk_r.sleeps), 1)
            self.assertAlmostEqual(clk_r.sleeps[0], 21.0, places=5)
            self.assertEqual(res_r["budget_consumption"]["this_session"]["weight_limit_cooldown_events"], 1)
            self.assertEqual(res_r["budget_consumption"]["this_session"]["last_observed_used_weight_1m"], 1)

            # 13c) Post-cooldown recovery check fails if weight does not drop below max_used_weight_1m
            srv_fail_rec = SyntheticBinanceServer()
            srv_fail_rec.register_month_all_streams("BTCUSDT", "2024-01")

            def h_weight_stuck(url: str, _c: int) -> Optional[HttpResponse]:
                if "/fapi/v1/exchangeInfo" in url:
                    payload = {"symbols": [{"symbol": "BTCUSDT", "status": "TRADING", "onboardDate": 1577836800000}]}
                    return HttpResponse(
                        200,
                        {"x-mbx-used-weight-1m": "2000", "Date": "Mon, 23 Nov 2026 00:00:40 GMT"},
                        json.dumps(payload).encode("utf-8"),
                        url,
                    )
                if "/fapi/v1/fundingInfo" in url:
                    return HttpResponse(200, {"x-mbx-used-weight-1m": "2000"}, b"[]", url)
                return None

            srv_fail_rec.override_handler = h_weight_stuck
            clk_fr = FakeClock()
            code_fr, res_fr = run_collect(
                cfg_rec,
                tmp / "out_w_failrec",
                transport=srv_fail_rec,
                clock_fn=clk_fr.clock,
                sleep_fn=clk_fr.sleep,
            )
            self.assertEqual(code_fr, EXIT_RUNTIME_OR_INTEGRITY_ERROR)
            self.assertEqual(res_fr["error"]["code"], "FAILED_EXCHANGE_WEIGHT_LIMIT_NOT_RECOVERED")
            self.assertEqual(len(srv_fail_rec.requests_seen), 2)

