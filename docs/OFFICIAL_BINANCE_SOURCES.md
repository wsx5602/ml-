# Official Binance USD-M Futures Public Data Sources & Terms

All network endpoints and archive schemas implemented in `cloud-market-data-collector` are strictly public, read-only market data endpoints documented by Binance. Zero private, account, order, credentialed, or paid third-party endpoints are permitted.

---

## 1. Allowed Domains & Official Documentation URLs

| Host | Endpoint / Path Pattern | Official Reference |
|---|---|---|
| `fapi.binance.com` | `GET /fapi/v1/exchangeInfo` (`onboardDate`, symbol status) | https://developers.binance.com/docs/derivatives/usds-margined-futures/market-data/rest-api/Exchange-Information |
| `fapi.binance.com` | `GET /fapi/v1/fundingRate` (`fundingTime`, `fundingRate`, `markPrice`) | https://developers.binance.com/docs/derivatives/usds-margined-futures/market-data/rest-api/Get-Funding-Rate-History |
| `fapi.binance.com` | `GET /fapi/v1/fundingInfo` (`adjustedFundingRateCap`, `adjustedFundingRateFloor`, `fundingIntervalHours`) | https://developers.binance.com/docs/derivatives/usds-margined-futures/market-data/rest-api/Get-Funding-Rate-Info |
| `fapi.binance.com` | General Info, Rate Limits, HTTP `429`/`418` rules | https://developers.binance.com/docs/derivatives/usds-margined-futures/general-info |
| `fapi.binance.com` | API Changelog (`markPrice` added to `/fapi/v1/fundingRate` around late Oct/Nov 2023) | https://developers.binance.com/docs/derivatives/change-log |
| `data.binance.vision` | `/data/futures/um/monthly/klines/{SYMBOL}/15m/{SYMBOL}-15m-{YYYY-MM}.zip` (+ `.CHECKSUM`) | https://github.com/binance/binance-public-data |
| `data.binance.vision` | `/data/futures/um/monthly/markPriceKlines/{SYMBOL}/1h/{SYMBOL}-1h-{YYYY-MM}.zip` (+ `.CHECKSUM`) | https://github.com/binance/binance-public-data |
| `data.binance.vision` | Public Archive Terms of Use | https://data.binance.vision/Binance_Vision-Terms_of_Use.pdf |

*(Reference check: `GET /fapi/v1/klines` and `GET /fapi/v1/markPriceKlines` are documented at https://developers.binance.com/docs/derivatives/usds-margined-futures/market-data/rest-api/Kline-Candlestick-Data and https://developers.binance.com/docs/derivatives/usds-margined-futures/market-data/rest-api/Mark-Price-Kline-Candlestick-Data; this collector fetches bulk monthly historical OHLCV/mark klines from `data.binance.vision` to verify `.CHECKSUM` SHA-256 digests and preserve immutable archive bytes.)*

---

## 2. Rate Limits, Retry Policy & IP Ban Rules (`fapi.binance.com`)

1. **General IP Weight Limit**: Binance USD-M Futures enforces an IP request-weight limit of **2,400 weight per minute** monitored via response header `X-MBX-USED-WEIGHT-1M`.
2. **Funding Endpoint Shared Bucket**: `GET /fapi/v1/fundingRate` (weight 1) and `GET /fapi/v1/fundingInfo` share a dedicated **500 requests per 5 minutes per IP** rate limit.
   - This collector enforces a proactive client-side sliding window (`max_funding_requests_per_5min <= 400` in shipped configs, below the 500/5min ceiling).
   - When `X-MBX-USED-WEIGHT-1M >= max_used_weight_1m` (`2000` in shipped configs), the collector **never sends an immediate follow-up request or a naive 1-second sleep**: it computes the required wait until the next UTC minute-window rollover (`+1.0s` buffer) from the response `Date` header (or UTC clock). If that wait exceeds `max_retry_after_seconds` or remaining wall-time budget, it aborts immediately (`FAILED_EXCHANGE_WEIGHT_LIMIT_REACHED`, exit `4`); otherwise it waits the full verified cooldown and aborts if weight on the recovery response fails to drop below `max_used_weight_1m` (`FAILED_EXCHANGE_WEIGHT_LIMIT_NOT_RECOVERED`, exit `4`).
3. **HTTP `429` / `503` & Strict `Retry-After` Compliance**:
   - Supports both non-negative numeric seconds and IMF-fixdate HTTP-date strings; negative, empty, non-finite (`NaN`/`inf`), or unparseable values fail closed immediately (`FAILED_INVALID_RETRY_AFTER`, exit `4`).
   - **Never shortens a server-requested `Retry-After` interval**: if the requested wait exceeds `max_retry_after_seconds` (`FAILED_RETRY_AFTER_EXCEEDS_MAX_WAIT`) or remaining `max_wall_time_seconds` (`FAILED_RETRY_AFTER_EXCEEDS_REMAINING_TIME`), the client aborts immediately without sending an early retry. Otherwise it waits the full requested duration up to finite `max_retries`.
4. **HTTP Redirects Prohibited**:
   - All HTTP `3xx` redirects (including same-host redirects) are refused at transport level (`_NoRedirectHandler`) without opening a second hop (`BLOCKED_HTTP_REDIRECT`, exit `2`).
5. **HTTP `418` (IP Auto-Ban)**: Triggered by ignoring `429` responses (ban duration 2 minutes to 3 days). Client **aborts immediately with zero retries** upon receiving HTTP `418` (`FAILED_IP_BAN_418`, exit code `4`).
6. **Infinite Retry Prohibition**: `max_retries` is strictly bounded in config schema (`0 <= max_retries <= 10`).

---

## 3. Historical Data Caveats Verified Against Official Specs & Workspace Precedents

1. **Timestamp Precision (`ms` vs `us`)**:
   - Binance Spot archives introduced 16-digit microsecond (`us`) timestamps starting `2025-01-01`.
   - Binance USD-M Futures archives (`futures/um`) and REST endpoints (`exchangeInfo.onboardDate`, `fundingRate.fundingTime`, kline `open_time`/`close_time`) natively use **13-digit millisecond (`ms`)** Unix epochs.
   - The parser rejects 10-digit (`s`) or 16-digit (`us`) epochs with `FAILED_TIMESTAMP_UNIT_MISMATCH`.
2. **Archive `fundingRate` vs REST `/fapi/v1/fundingRate` (`markPrice`)**:
   - `data.binance.vision` monthly `fundingRate` CSVs (`calc_time, funding_interval_hours, last_funding_rate`) do **not** include the settlement mark price (`markPrice`).
   - Therefore, funding settlements MUST be collected via `GET https://fapi.binance.com/fapi/v1/fundingRate`, which includes `markPrice` for events after Binance's late-2023 changelog update (Oct/Nov 2023).
   - If historical pre-Nov-2023 REST rows return missing, empty, `null`, or non-positive `markPrice`, the collector **MUST NOT substitute `mark_1h` close or zero-fill**; it preserves the raw JSON pages, marks affected units `INCOMPLETE_MISSING_SETTLEMENT_MARK_PRICE`, sets `manifest.status = "INCOMPLETE"`, and exits with code `3`.
3. **Variable Funding Intervals (No Fixed 8h Assumption)**:
   - Binance dynamically switches individual contracts between `8h`, `4h`, `2h`, or `1h` intervals during extreme volatility (documented in `/fapi/v1/fundingInfo` and observed locally in `R30 funding_schedule_comparison.json` for `SOLUSDT` in `2022-11` with 75 non-8h events and 0–47 ms subsecond offsets).
   - `validation.assume_fixed_8h_funding` is hard-enforced to `false`. Every settlement preserves exact millisecond `fundingTime` and computes actual `observed_interval_hours = (curr_ms - prev_ms) / 3600000`.
4. **Terms of Use Compliance**:
   - Usage of `data.binance.vision` and public REST endpoints is subject to `Binance_Vision-Terms_of_Use.pdf` and Binance API Terms (non-abusive public market-data access, honoring HTTP `429`/`418`, zero credential sharing, zero order/account calls).
