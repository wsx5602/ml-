# Cloud Market Data Collector (`cloud-market-data-collector` v1.2.0)

Cross-platform (Windows & Linux) public market data collector for **Binance USD-M Perpetual Futures** (`BTCUSDT`, `ETHUSDT`, `SOLUSDT`, `BNBUSDT`, `XRPUSDT`), designed for deterministic execution in Codex Cloud and checksum-verified export to local environments.

- **Pure Python standard library (`Python >=3.11`, verified on `Python 3.13.2`)** — zero third-party runtime dependencies, zero API keys, zero order endpoints, zero paid services.
- **Fail-closed OOS & boundary enforcement**: inspects full monthly archive bounds and explicit `[requested_start_utc, requested_end_exclusive_utc)` ranges before any HTTP request; permanently rejects any request or archive touching `>= 2025-10-13T00:00:00Z` or `< 2021-01-01T00:00:00Z` (never substitutes post-download filtering for OOS blocking), and inspects kline `open_time` / `close_time` separately from `fundingTime`.
- **Irregular funding & duplicate safety**: preserves variable funding intervals and subsecond timestamps without misclassifying non-8h intervals as fixed-grid missing bars; deduplicates identical page-boundary overlap while failing closed on conflicting duplicate values.
- **Hardened execution budgets & rate compliance**:
  - **Strict `Retry-After` non-reduction**: parses non-negative numbers and IMF-fixdate HTTP-dates, fails closed on negative/malformed values, never shortens server wait times, and aborts immediately without early retries if `Retry-After` exceeds `max_retry_after_seconds` or remaining wall time.
  - **Cumulative job-level budgets**: tracks per-session vs cumulative HTTP requests and downloaded bytes atomically into `checkpoint.json` before calls and during error/crash unwinding (`ABORTED_ABNORMALLY` / `FAILED`), enforcing cumulative ceilings across `--resume`.
  - **Prohibited redirects & full wire accounting**: refuses HTTP 3xx redirects without following hops, accounts failed/redirect response bodies and partial transport bytes (`bytes_received`) toward byte budgets, clamps connect/read/per-chunk socket timeouts to remaining overall deadline, and enforces UTC minute-window reset cooldowns or explicit aborts when `X-MBX-USED-WEIGHT-1M >= max_used_weight_1m`.
- **Immutable raw preservation + disk-byte SHA-256**: hashes actual bytes on disk (`"rb"`) after atomic write, preventing CRLF/LF string-hash discrepancies across Windows and Linux.
- **Honest status & exit codes**: never promotes missing `markPrice`, gapped/duplicated streams, or partial failures to `COMPLETE`.

---

## Quickstart (Windows & Linux)

Run from the root of this repository using `-B` to avoid polluting the working tree with `__pycache__`:

```bash
# 1. Offline preflight (0 network calls)
python -B -m collector preflight --config configs/pilot_1m_5sym_2024_01.json

# 2. Collect (or resume with --resume)
python -B -m collector collect --config configs/pilot_1m_5sym_2024_01.json --out-dir ./outputs/pilot_2024_01
python -B -m collector collect --config configs/pilot_1m_5sym_2024_01.json --out-dir ./outputs/pilot_2024_01 --resume

# 3. Offline integrity verification
python -B -m collector verify --package-dir ./outputs/pilot_2024_01 --require-complete

# 4. Deterministic .tar.gz + .sha256 export
python -B -m collector export-bundle --package-dir ./outputs/pilot_2024_01 --archive-path ./outputs/pilot_2024_01.tar.gz
```

On Linux, you can verify checksums independently with GNU `sha256sum`:
```bash
(cd ./outputs/pilot_2024_01 && sha256sum -c SHA256SUMS.txt)
```

---

## Exit Codes

| Exit Code | Meaning |
|---|---|
| `0` | `PREFLIGHT_PASS`, `COMPLETE`, `VERIFY_PASS`, or `EXPORT_PASS` |
| `2` | Policy / Config / Allowlist / OOS / Resume-Scope Rejection (before transport) |
| `3` | `INCOMPLETE` (missing settlement `markPrice`, `404` stream gap, boundary gap/duplicate, or partial pending units) |
| `4` | Runtime / Network Exhaustion / HTTP `418` Ban / Budget Exhaustion / Checksum or Integrity Failure |

---

## Running Offline Synthetic Tests

Zero external network requests; all tests use synthetic payloads and `tempfile.TemporaryDirectory()`:

```bash
python -B -m unittest discover -s tests -v
```

---

## Documentation Index

- [Data Contract & Budgets](docs/DATA_CONTRACT_AND_BUDGET.md)
- [Official Binance Sources & Terms](docs/OFFICIAL_BINANCE_SOURCES.md)
- [Cloud Execution Handoff Runbook](docs/CLOUD_HANDOFF_RUNBOOK.md)
