# Data Contract, Period Boundaries, and Collection Budgets

## 1. Universe & Period Boundaries (Fail-Closed Policy)

### Allowed Universe
- **Allowed Symbols (Hard Allowlist)**: `BTCUSDT`, `ETHUSDT`, `SOLUSDT`, `BNBUSDT`, `XRPUSDT` (Binance USD-M Perpetual Futures).
- **Disallowed Symbols**: Any other symbol is rejected pre-transport with exit code `2` (`BLOCKED_DISALLOWED_SYMBOL`).

### Allowed vs Forbidden Time Boundaries (Derived Strictly From Non-Sealed Audits)
1. **Allowed Pre-OOS Window**: `2021-01-01T00:00:00Z <= t < 2025-10-13T00:00:00Z`
   - Lower bound `2021-01-01T00:00:00Z` (`1609459200000` ms) confirmed from non-sealed `R30` `per_file_audit.json` and `DAILY_ML_AND_CLOUD_DATA_READINESS_ADDENDUM.md` §3.2.
   - Upper exclusive OOS boundary `2025-10-13T00:00:00Z` (`1760313600000` ms) confirmed from non-sealed `W1_STAGE_A_TO_STAGE_B_INPUT_MANIFEST.json`.
   - Primary pre-2024 collection target: explicit half-open window `2021-01-01T00:00:00Z <= open_time < 2024-01-01T00:00:00Z` (`start_month = "2021-01"`, `end_month = "2023-12"`), while actual per-symbol/per-stream start depends on exchange `onboardDate` and stream availability.
2. **Forbidden OOS Window (`t >= 2025-10-13T00:00:00Z`) & Full-Archive Pre-Transport Check**:
   - **Permanently forbidden**, including re-downloading the same symbols from Binance endpoints.
   - Both the declared half-open range (`requested_end_exclusive_utc`) and the **full monthly Vision archive upper bound** (`last_month_next_ms >= oos_forbidden_start_ms`) are verified *before* any network request (`BLOCKED_OOS_FORBIDDEN_PERIOD`, exit `2`). Post-download filtering never substitutes for pre-transport rejection.
   - At payload validation, kline `open_time_ms`, `raw_close_time_ms`, and `logical_close_ms` (`open_time + interval_ms`), as well as funding `funding_time_ms`, are checked separately; any OOS boundary contact or crossing triggers `FAILED_OOS_CONTAMINATION_IN_PAYLOAD` (`exit 4`).
3. **Unclear Lower Boundary (`t < 2021-01-01T00:00:00Z`)**:
   - Rejected pre-transport (`BLOCKED_UNCLEAR_LOWER_BOUNDARY`, exit code `2`) because pre-2021 non-sealed cross-audit boundaries are not established.

---

## 2. Stream Data Contracts (UTF-8, LF `\n`, Decimal Strings, UTC)

### Stream A: `exec_15m` (Trade Execution 15m OHLCV)
- **Source**: `https://data.binance.vision/data/futures/um/monthly/klines/{SYM}/15m/{SYM}-15m-{YYYY-MM}.zip` (+ `.CHECKSUM`)
- **Refined Columns**:
  `open_time_ms,open_time_utc,raw_close_time_ms,logical_close_utc,open,high,low,close,volume,quote_volume,trade_count,taker_buy_base_volume,taker_buy_quote_volume`
- **Invariants**:
  - `open_time_ms` & `raw_close_time_ms`: 13-digit ms epochs (`open_time_ms % 900000 == 0`, `raw_close_time_ms == open_time_ms + 899999`).
  - `logical_close_utc = open_time_utc + 15m` (`< 2025-10-13T00:00:00Z`).
  - OHLC strictly positive finite `Decimal`, `high >= max(open, close, low)`, `low <= min(open, close, high)`; volumes/counts finite `>= 0`.
  - Zero duplicate bars, zero non-monotonic bars, zero gaps (after listing `onboardDate`).

### Stream B: `mark_1h` (Mark Price 1h OHLC)
- **Source**: `https://data.binance.vision/data/futures/um/monthly/markPriceKlines/{SYM}/1h/{SYM}-1h-{YYYY-MM}.zip` (+ `.CHECKSUM`)
- **Refined Columns**:
  `open_time_ms,open_time_utc,raw_close_time_ms,logical_close_utc,open,high,low,close`
- **Invariants**:
  - `open_time_ms % 3600000 == 0`, `raw_close_time_ms == open_time_ms + 3599999`, `logical_close_utc = open_time_utc + 1h`.
  - OHLC strictly positive finite `Decimal`, valid envelope, contiguous hourly grid after listing.

### Stream C: `funding_settlement` (Funding Settlement Time, Rate & Mark Price)
- **Source**: `GET https://fapi.binance.com/fapi/v1/fundingRate` (`symbol`, `startTime`, `endTime`, `limit<=1000`)
- **Refined Columns**:
  `funding_time_ms,funding_time_utc,funding_rate,settlement_mark_price,observed_interval_hours,rate_type`
- **Invariants**:
  - `funding_time_ms`: 13-digit ms epoch preserved verbatim (including subsecond ms offsets; zero rounding).
  - `observed_interval_hours`: computed directly as `(curr_ms - prev_ms) / 3600000`; never assumes a fixed 8h grid. Irregular schedules (`1h`, `2h`, `4h`, `12h`, etc.) increment `irregular_interval_count` (and log non-failing warnings above `anomalous_funding_interval_warning_hours = 10.0`) rather than misclassifying variable cadence as missing fixed-grid bars; genuine omissions such as page-cap truncation, `HTTP 404`, or empty active months still fail completeness (`exit 3`).
  - **Duplicate Event Distinction**: Identical page-boundary overlap across pagination calls (`page_boundary_identical_duplicate_count`) is counted and deduplicated cleanly; conflicting duplicates at the same `funding_time_ms` (`conflicting_duplicate_count > 0`) fail closed (`FAILED_CONFLICTING_DUPLICATE_EVENT`, exit `4`) with raw evidence preserved.
  - `settlement_mark_price` (`markPrice`): **MUST be finite positive `Decimal`**. Any missing, `null`, empty, or `<= 0` settlement mark price triggers `INCOMPLETE_MISSING_SETTLEMENT_MARK_PRICE` (raw JSON preserved, refined CSV withheld, `manifest.status = "INCOMPLETE"`, exit code `3`). Zero substitution or zero-fill is permitted.

---

## 3. Immutable Raw vs Refined Separation & Disk-Byte SHA-256

```text
<out_dir>/
├── exchange_metadata/        # Immutable raw exchangeInfo.json & fundingInfo.json
├── raw/                      # Immutable raw .zip, .CHECKSUM, and REST page_NNN.json
├── refined/
│   ├── monthly/              # Verified normalized LF-only monthly CSVs (only when unit is clean)
│   └── merged/               # Cross-month stitched CSVs (only when all active months verified)
├── checkpoint.json           # Atomic per-unit checkpoint for safe --resume
├── manifest.json             # Complete audit trail: URLs, bounds, schemas, gaps, hashes, verdict
└── SHA256SUMS.txt            # Disk-byte SHA-256 (`rb`) over all tracked relative POSIX paths (LF)
```

- **Disk-Byte Hashing**: Every hash in `manifest.json` and `SHA256SUMS.txt` is computed *after* atomic file write by re-reading actual bytes in `"rb"` mode (`sha256_file_from_disk`), never from pre-write Python strings.
- **No Success Masking**: Exit code `0` (`COMPLETE`) occurs iff zero runtime errors, zero gaps/duplicates, zero missing settlement mark prices, and all cross-month boundaries pass. Exit code `2` = policy/config rejection; `3` = `INCOMPLETE`; `4` = runtime/network/budget/checksum/integrity error.

---

## 4. Budget Profiles

| Parameter | Pilot (`2024-01`, 1m x 5 sym) | Full Pre-2024 (`2021-01..2023-12`, 36m x 5 sym) |
|---|---|---|
| Config File | `configs/pilot_1m_5sym_2024_01.json` | `configs/full_pre2024_2021_01_to_2023_12.json` |
| Planned Units | 15 (3 streams x 5 symbols x 1m) | 540 (3 streams x 5 symbols x 36m) |
| Est. Min HTTP Requests | 27 | 902 |
| `max_http_requests` | 45 | 1,200 |
| `max_compressed_download_bytes` | 20 MiB (`20,971,520` B) | 150 MiB (`157,286,400` B) |
| `max_single_response_bytes` | 8 MiB (`8,388,608` B) | 16 MiB (`16,777,216` B) |
| `max_single_uncompressed_bytes` | 32 MiB (`33,554,432` B) | 32 MiB (`33,554,432` B) |
| `max_total_storage_bytes` | 64 MiB (`67,108,864` B) | 512 MiB (`536,870,912` B) |
| `max_wall_time_seconds` | `300.0` s (5 min) | `1,800.0` s (30 min) |
| Timeouts (`connect` / `read`) | 10s / 30s (clamped to remaining deadline per op/chunk) | 10s / 30s (clamped to remaining deadline per op/chunk) |
| Finite Retries | `max_retries = 3` (strict non-reduced `Retry-After`, abort if `> 60s` or `> rem_wall`) | `max_retries = 3` (strict non-reduced `Retry-After`, abort if `> 60s` or `> rem_wall`) |
| Rate Guards | `400 req / 5min`; minute-rollover gate/abort on `used_weight_1m >= 2000`; HTTP `418` abort | `400 req / 5min`; minute-rollover gate/abort on `used_weight_1m >= 2000`; HTTP `418` abort |
| Explicit Rationale | Recorded verbatim in `budgets.budget_rationale` & `manifest.json` | Recorded verbatim in `budgets.budget_rationale` & `manifest.json` |

### Job-Wide Cumulative Enforcement & Wire Accounting Rules
- **Session vs Cumulative Separation**: `manifest.json -> budget_consumption` separates `this_session` counters from job-total `cumulative` counters persisted in `checkpoint.json` before every HTTP request and during error/crash unwinding (`ABORTED_ABNORMALLY` / `FAILED`). Resuming with `--resume` enforces `max_http_requests` and `max_compressed_download_bytes` against `cumulative` totals and validates that `cumulative.compressed_bytes_downloaded` is never below verified raw disk artifact bytes.
- **No Uncounted Bytes or Redirects**: HTTP `3xx` redirects are refused without following hops (`BLOCKED_HTTP_REDIRECT`), and all response bytes—including 3xx/4xx/5xx bodies and partial stream bytes received prior to timeout or disconnect—are accumulated immediately.
- **Overall Execution Deadline**: Connect timeout, read timeout, backoff/cooldown waits, and per-chunk socket reads are bounded by remaining `max_wall_time_seconds`, stopping immediately if a late-arriving chunk crosses the deadline.
