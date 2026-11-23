# Codex Cloud Execution Handoff & Local Verification Runbook

This runbook specifies the **three strictly separated commands** for executing collection in Codex Cloud (Linux) and reconciling the exported bundle back on Windows local.

> **Execution Gate**: Command 3 (Full Pre-2024 Collection) MUST NOT begin until Command 1 (Offline Preflight) and Command 2 (Fixed 1-Month Pilot + Local Download + Hash Reconciliation) succeed with exit code `0`.

---

## Command 1 — Offline Preflight Check (Zero Network Calls)

Validates schema, symbol allowlist, OOS boundary (`< 2025-10-13T00:00:00Z`), unclear lower boundary (`>= 2021-01-01T00:00:00Z`), HTTPS/domain allowlists, finite retry bounds, planned URLs, and budget sufficiency without making any network call.

```bash
python3 -B -m collector preflight \
  --config configs/pilot_1m_5sym_2024_01.json \
  --out-dir /tmp/collector_preflight_pilot
```

*(Also run for the full config prior to Command 3:)*
```bash
python3 -B -m collector preflight \
  --config configs/full_pre2024_2021_01_to_2023_12.json \
  --out-dir /tmp/collector_preflight_full
```

- **Expected Outputs**:
  - Stdout JSON with `"status": "PREFLIGHT_PASS"`, `"exit_code": 0`, `"network_requests_executed": 0`.
  - `<out-dir>/preflight_report.json` listing `planned_units_count`, `estimated_min_http_requests`, and `configured_budgets`.
- **Abort Conditions**:
  - Any exit code `!= 0` (e.g., `2` for policy/period/symbol/budget failure). Do NOT modify allowlists or OOS bounds; report error and stop.
- **Consumption Logging**:
  - Record `network_requests_executed = 0`, `config_sha256`, `estimated_min_http_requests`, and `estimated_worst_case_http_requests`.

---

## Command 2 — Fixed Common 1-Month × 5-Symbol Pilot (`2024-01`)

Collects `BTCUSDT`, `ETHUSDT`, `SOLUSDT`, `BNBUSDT`, `XRPUSDT` for `2024-01` across all 3 required streams (`exec_15m`, `mark_1h`, `funding_settlement`), verifies integrity, and builds a portable export bundle.

```bash
python3 -B -m collector collect \
  --config configs/pilot_1m_5sym_2024_01.json \
  --out-dir /tmp/collector_pilot_2024_01

python3 -B -m collector verify \
  --package-dir /tmp/collector_pilot_2024_01 \
  --require-complete

python3 -B -m collector export-bundle \
  --package-dir /tmp/collector_pilot_2024_01 \
  --archive-path /tmp/collector_pilot_2024_01.tar.gz
```

*(If interrupted mid-run due to transient network error, resume without re-downloading verified units via `python3 -B -m collector collect --config configs/pilot_1m_5sym_2024_01.json --out-dir /tmp/collector_pilot_2024_01 --resume`.)*

- **Expected Outputs**:
  - `/tmp/collector_pilot_2024_01/manifest.json` (`status: "COMPLETE"`, `exit_code: 0`, `unit_status_counts.verified_complete: 15`)
  - `/tmp/collector_pilot_2024_01/SHA256SUMS.txt` (LF relative POSIX paths)
  - `/tmp/collector_pilot_2024_01/refined/merged/{SYM}_{exec_15m|mark_1h|funding_settlement}.csv` (15 merged files)
  - `/tmp/collector_pilot_2024_01.tar.gz` and `/tmp/collector_pilot_2024_01.tar.gz.sha256`
- **Abort Conditions**:
  - Exit code `2` (policy rejection or refused `BLOCKED_HTTP_REDIRECT`), `3` (`INCOMPLETE` e.g. missing settlement markPrice or gaps), `4` (HTTP `418` IP ban, checksum mismatch, unrecovered/excessive exchange weight limit, `Retry-After > max_retry_after_seconds` / remaining time, or cumulative budget/retry exhaustion).
  - Resuming via `--resume` inherits prior `cumulative_consumption` from `checkpoint.json` (even after an abnormal crash) and only spends remaining `max_http_requests` / `max_compressed_download_bytes` budget.
- **Consumption Logging**:
  - Extract from `manifest.json -> budget_consumption`: `this_session.*` and `cumulative.*` (`http_requests_attempted`, `http_requests_succeeded`, `retry_count`, `total_sleep_seconds`, `compressed_bytes_downloaded`, `uncompressed_bytes_extracted`, `elapsed_wall_seconds`, `remaining_http_requests`, `remaining_compressed_download_bytes`, `last_session_status`), `total_disk_bytes_on_disk`, and `this_session.max_observed_used_weight_1m`.

### Mandatory Local Download & Hash Reconciliation Gate (Before Command 3)
1. Download `collector_pilot_2024_01.tar.gz` and `collector_pilot_2024_01.tar.gz.sha256` to a fresh local directory outside `oos_data` and existing frozen folders.
2. Verify outer archive SHA-256 on Windows PowerShell:
   ```powershell
   (Get-FileHash .\collector_pilot_2024_01.tar.gz -Algorithm SHA256).Hash.ToLower()
   Get-Content .\collector_pilot_2024_01.tar.gz.sha256
   ```
3. Extract and run the collector's cross-platform verifier locally:
   ```powershell
   mkdir .\pilot_extracted
   tar -xzf .\collector_pilot_2024_01.tar.gz -C .\pilot_extracted
   python -B -m collector verify --package-dir .\pilot_extracted --require-complete
   ```
4. Proceed to Command 3 **only after** `VERIFY_PASS` (`exit_code = 0`) locally.

---

## Command 3 — Budgeted Full Pre-2024 Collection (`2021-01-01 <= open_time < 2024-01-01`)

Runs the bounded 36-month pre-2024 expansion collection across `BTCUSDT`, `ETHUSDT`, `SOLUSDT`, `BNBUSDT`, `XRPUSDT` (`540` units, `max_http_requests = 1200`, `max_compressed_download_bytes = 150 MiB`, `max_total_storage_bytes = 512 MiB`, `max_wall_time_seconds = 1800.0`).

```bash
python3 -B -m collector collect \
  --config configs/full_pre2024_2021_01_to_2023_12.json \
  --out-dir /tmp/collector_full_pre2024

# Resume without re-fetching verified units if interrupted by transient error or time/retry cutoff:
python3 -B -m collector collect \
  --config configs/full_pre2024_2021_01_to_2023_12.json \
  --out-dir /tmp/collector_full_pre2024 \
  --resume

python3 -B -m collector verify \
  --package-dir /tmp/collector_full_pre2024
```

*(Bundle export after verification: if all units including `markPrice` are complete, omit `--allow-incomplete`; if historical pre-2023-11 funding `markPrice` is absent from Binance REST API and the run legitimately terminates with `status = "INCOMPLETE"`, `exit_code = 3`, inspect `manifest.json` first and only export verified evidence with `--allow-incomplete` if instructed:)*
```bash
# When status == COMPLETE (exit 0):
python3 -B -m collector export-bundle \
  --package-dir /tmp/collector_full_pre2024 \
  --archive-path /tmp/collector_full_pre2024.tar.gz

# If historical funding settlement markPrice before late 2023 is omitted by Binance (status == INCOMPLETE, exit 3):
# DO NOT substitute prices; bundle raw evidence & complete klines only if explicitly requested:
python3 -B -m collector export-bundle \
  --package-dir /tmp/collector_full_pre2024 \
  --archive-path /tmp/collector_full_pre2024_incomplete_evidence.tar.gz \
  --allow-incomplete
```

- **Expected Outputs**:
  - `/tmp/collector_full_pre2024/manifest.json` detailing per-symbol `onboard_date_utc`, `first_available_utc`, `first_populated_settlement_mark_utc`, `missing_settlement_mark_price_count`, `irregular_interval_count`, `page_boundary_identical_duplicate_count`, `conflicting_duplicate_count`, `unit_status_counts`, and full `SHA256SUMS.txt`.
  - Pre-listing months (e.g., if an asset onboarded mid-period) recorded as `SKIPPED_PRE_LISTING` with zero fabricated rows.
  - Pre-Nov-2023 funding rows missing `markPrice` preserved in `raw/funding_settlement/` and flagged `INCOMPLETE_MISSING_SETTLEMENT_MARK_PRICE` (`exit 3`), never silently patched.
- **Abort Conditions**:
  - Exit code `2` on policy/redirect rejection (`BLOCKED_HTTP_REDIRECT`); exit code `4` on HTTP `418` IP ban, exhausted finite retries, `Retry-After` exceeds wait/wall limit, unrecovered/excessive exchange weight wait, conflicting duplicate event, checksum mismatch, timestamp unit mismatch (`us`/`s`), or cumulative HTTP/download/storage/wall-time budget breach.
  - On transient network interruption (`exit 4`) or abnormal termination, inspect `manifest.json` / `checkpoint.json` and resume with `--resume` within remaining cumulative budgets without duplicating verified units.
- **Consumption Logging**:
  - Record final `budget_consumption` (`this_session` vs `cumulative` including `remaining_http_requests`, `remaining_compressed_download_bytes`, `elapsed_wall_seconds`, `last_session_status`, `total_disk_bytes_on_disk`), `unit_status_counts`, and archive `.tar.gz` SHA-256.
