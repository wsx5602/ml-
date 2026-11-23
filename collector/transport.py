"""Allowlisted HTTPS transport, rate-limit handling, finite retries, and budget tracking."""

from __future__ import annotations

import email.utils
import http.client
import math
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, Optional, Tuple

from .config import CollectorConfig
from .constants import (
    COLLECTOR_VERSION,
    EXIT_POLICY_REJECTED,
    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
    FAPI_READONLY_PATHS,
    FORBIDDEN_AUTH_HEADERS,
    FORBIDDEN_AUTH_QUERY_RE,
    HARD_ALLOWED_HOSTS,
    STREAM_TO_VISION_PATH_SPEC,
    VISION_MONTHLY_PATH_RE,
    CollectorError,
)
from .time_utils import detect_epoch_unit, month_bounds_ms

_ALLOWED_VISION_SPECS = frozenset(STREAM_TO_VISION_PATH_SPEC.values())


@dataclass(frozen=True)
class HttpResponse:
    """Normalized HTTP response returned by a transport implementation."""

    status: int
    headers: Dict[str, str]
    body: bytes
    final_url: str


TransportCallable = Callable[[str, float, float, int, Tuple[str, ...]], HttpResponse]
UrlValidatorCallable = Callable[[str], urllib.parse.SplitResult]


def validate_request_url(
    url: str,
    *,
    allowed_hosts: Tuple[str, ...],
    allowed_symbols: Tuple[str, ...],
    allowed_start_ms: int,
    oos_forbidden_start_ms: int,
) -> urllib.parse.SplitResult:
    """Validate scheme, domain, path, auth absence, symbol allowlist, and time boundaries."""
    if not isinstance(url, str) or not url.strip():
        raise CollectorError("BLOCKED_EMPTY_URL", "Empty request URL rejected.", EXIT_POLICY_REJECTED)
    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.scheme.lower() != "https":
        raise CollectorError(
            "BLOCKED_DISALLOWED_SCHEME",
            f"Non-HTTPS URL rejected before transport: {url}",
            EXIT_POLICY_REJECTED,
        )
    if parsed.username or parsed.password:
        raise CollectorError(
            "BLOCKED_CREDENTIALS_IN_URL",
            f"Credentials in URL rejected before transport: {url}",
            EXIT_POLICY_REJECTED,
        )
    host = (parsed.hostname or "").lower()
    if host not in allowed_hosts or host not in HARD_ALLOWED_HOSTS:
        raise CollectorError(
            "BLOCKED_DISALLOWED_DOMAIN",
            f"Domain '{host}' is not allowlisted ({allowed_hosts}): {url}",
            EXIT_POLICY_REJECTED,
        )
    if parsed.query and FORBIDDEN_AUTH_QUERY_RE.search(parsed.query):
        raise CollectorError(
            "BLOCKED_API_KEY_IN_REQUEST",
            f"Forbidden credential or auth parameter detected in URL: {url}",
            EXIT_POLICY_REJECTED,
        )

    if host == "data.binance.vision":
        if parsed.query:
            raise CollectorError(
                "BLOCKED_UNEXPECTED_VISION_QUERY",
                f"Unexpected query string on Vision archive URL: {url}",
                EXIT_POLICY_REJECTED,
            )
        m = VISION_MONTHLY_PATH_RE.match(parsed.path)
        if not m:
            raise CollectorError(
                "BLOCKED_DISALLOWED_VISION_PATH",
                f"Vision URL does not match monthly archive allowlist: {url}",
                EXIT_POLICY_REJECTED,
            )
        dataset_type, symbol, interval, ym, _cs = m.groups()
        if symbol not in allowed_symbols:
            raise CollectorError(
                "BLOCKED_DISALLOWED_SYMBOL",
                f"Symbol '{symbol}' in Vision URL not allowlisted: {url}",
                EXIT_POLICY_REJECTED,
            )
        if (dataset_type, interval) not in _ALLOWED_VISION_SPECS:
            raise CollectorError(
                "BLOCKED_DISALLOWED_STREAM",
                f"Vision path spec ({dataset_type}, {interval}) not permitted: {url}",
                EXIT_POLICY_REJECTED,
            )
        m_start_ms, _m_end_ms, m_next_ms = month_bounds_ms(ym)
        if m_start_ms < allowed_start_ms:
            raise CollectorError(
                "BLOCKED_UNCLEAR_LOWER_BOUNDARY",
                f"Vision archive month '{ym}' precedes allowed_start_ms={allowed_start_ms}: {url}",
                EXIT_POLICY_REJECTED,
            )
        if m_next_ms >= oos_forbidden_start_ms:
            raise CollectorError(
                "BLOCKED_OOS_FORBIDDEN_PERIOD",
                f"Vision archive month '{ym}' full-archive upper boundary touches or crosses forbidden OOS boundary: {url}",
                EXIT_POLICY_REJECTED,
            )
    elif host == "fapi.binance.com":
        if parsed.path not in FAPI_READONLY_PATHS:
            raise CollectorError(
                "BLOCKED_DISALLOWED_ENDPOINT",
                f"Endpoint '{parsed.path}' is not an allowed public read-only market endpoint: {url}",
                EXIT_POLICY_REJECTED,
            )
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, strict_parsing=False)
        if parsed.path == "/fapi/v1/fundingRate":
            allowed_keys = {"symbol", "startTime", "endTime", "limit"}
            unknown_keys = set(qs.keys()) - allowed_keys
            if unknown_keys:
                raise CollectorError(
                    "BLOCKED_UNEXPECTED_QUERY_PARAM",
                    f"Unexpected query params {sorted(unknown_keys)} on {parsed.path}",
                    EXIT_POLICY_REJECTED,
                )
            for req_key in ("symbol", "startTime", "endTime"):
                if req_key not in qs or len(qs[req_key]) != 1:
                    raise CollectorError(
                        "BLOCKED_MISSING_FUNDING_BOUNDS",
                        f"Query parameter '{req_key}' is required once on {parsed.path}: {url}",
                        EXIT_POLICY_REJECTED,
                    )
            sym = qs["symbol"][0]
            if sym not in allowed_symbols:
                raise CollectorError(
                    "BLOCKED_DISALLOWED_SYMBOL",
                    f"Symbol '{sym}' in REST request not allowlisted: {url}",
                    EXIT_POLICY_REJECTED,
                )
            s_val, s_unit = detect_epoch_unit(qs["startTime"][0], context="query startTime")
            e_val, e_unit = detect_epoch_unit(qs["endTime"][0], context="query endTime")
            if s_unit != "ms" or e_unit != "ms":
                raise CollectorError(
                    "BLOCKED_INVALID_QUERY_TIMESTAMP_UNIT",
                    f"Query startTime/endTime must be ms epoch in {url}",
                    EXIT_POLICY_REJECTED,
                )
            if s_val < allowed_start_ms:
                raise CollectorError(
                    "BLOCKED_UNCLEAR_LOWER_BOUNDARY",
                    f"REST startTime {s_val} < allowed_start_ms {allowed_start_ms}: {url}",
                    EXIT_POLICY_REJECTED,
                )
            if e_val >= oos_forbidden_start_ms or s_val > e_val:
                raise CollectorError(
                    "BLOCKED_OOS_FORBIDDEN_PERIOD",
                    f"REST bounds [{s_val}, {e_val}] cross forbidden OOS cutoff {oos_forbidden_start_ms}: {url}",
                    EXIT_POLICY_REJECTED,
                )
            if "limit" in qs:
                if len(qs["limit"]) != 1 or not qs["limit"][0].isdigit():
                    raise CollectorError("BLOCKED_INVALID_QUERY_PARAM", f"Invalid limit in {url}", EXIT_POLICY_REJECTED)
                lim = int(qs["limit"][0])
                if not (1 <= lim <= 1000):
                    raise CollectorError("BLOCKED_INVALID_QUERY_PARAM", f"limit={lim} outside [1, 1000]", EXIT_POLICY_REJECTED)
        elif parsed.path == "/fapi/v1/exchangeInfo":
            if qs:
                raise CollectorError(
                    "BLOCKED_UNEXPECTED_QUERY_PARAM",
                    f"Unexpected query params on {parsed.path}: {url}",
                    EXIT_POLICY_REJECTED,
                )
        elif parsed.path == "/fapi/v1/fundingInfo":
            if set(qs.keys()) - {"symbol"}:
                raise CollectorError(
                    "BLOCKED_UNEXPECTED_QUERY_PARAM",
                    f"Unexpected query params on {parsed.path}: {url}",
                    EXIT_POLICY_REJECTED,
                )
            if "symbol" in qs and (len(qs["symbol"]) != 1 or qs["symbol"][0] not in allowed_symbols):
                raise CollectorError(
                    "BLOCKED_DISALLOWED_SYMBOL",
                    f"Disallowed symbol on {parsed.path}: {url}",
                    EXIT_POLICY_REJECTED,
                )

    return parsed


class _SplitTimeoutHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection enforcing separate connect/read timeouts and overall wall-clock deadline."""

    def __init__(
        self,
        host: str,
        port: Optional[int] = None,
        *,
        connect_timeout: float,
        read_timeout: float,
        clock_fn: Callable[[], float],
        deadline_monotonic: float,
        context: Optional[ssl.SSLContext] = None,
    ) -> None:
        rem = deadline_monotonic - float(clock_fn())
        if rem <= 0.0:
            raise CollectorError(
                "FAILED_TIME_BUDGET_EXCEEDED",
                "Overall wall-time deadline exhausted before HTTPS connection initialization.",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        super().__init__(host, port=port, timeout=min(connect_timeout, rem), context=context)
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._clock_fn = clock_fn
        self._deadline_monotonic = deadline_monotonic

    def connect(self) -> None:
        rem = self._deadline_monotonic - float(self._clock_fn())
        if rem <= 0.0:
            raise CollectorError(
                "FAILED_TIME_BUDGET_EXCEEDED",
                f"Overall wall-time deadline exhausted before TCP connect to {self.host}.",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        self.timeout = min(self._connect_timeout, rem)
        super().connect()
        rem_after = self._deadline_monotonic - float(self._clock_fn())
        if rem_after <= 0.0:
            self.close()
            raise CollectorError(
                "FAILED_TIME_BUDGET_EXCEEDED",
                f"Overall wall-time deadline exhausted during connect/TLS handshake to {self.host}.",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        if self.sock is not None:
            self.sock.settimeout(min(self._read_timeout, rem_after))


class _SplitTimeoutHTTPSHandler(urllib.request.HTTPSHandler):
    """urllib HTTPSHandler building split-timeout, deadline-bounded HTTPS connections."""

    def __init__(
        self,
        *,
        connect_timeout: float,
        read_timeout: float,
        clock_fn: Callable[[], float],
        deadline_monotonic: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(context=context)
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._clock_fn = clock_fn
        self._deadline_monotonic = deadline_monotonic

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        def _factory(host: str, **kwargs: object) -> _SplitTimeoutHTTPSConnection:
            port = kwargs.get("port")
            return _SplitTimeoutHTTPSConnection(
                host,
                port=port if isinstance(port, int) else None,
                connect_timeout=self._connect_timeout,
                read_timeout=self._read_timeout,
                clock_fn=self._clock_fn,
                deadline_monotonic=self._deadline_monotonic,
                context=self._context,
            )

        return self.do_open(_factory, req)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler refusing all HTTP 3xx hops so redirects are never silently followed."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> Optional[urllib.request.Request]:
        return None


_POSITIVE_NUMBER_RE = re.compile(r"^\d+(?:\.\d+)?$")


def parse_retry_after_header(raw_value: str, *, now_utc: datetime) -> float:
    """Strictly parse Retry-After (non-negative seconds or HTTP-date) without clamping."""
    if not isinstance(raw_value, str):
        raise CollectorError(
            "FAILED_INVALID_RETRY_AFTER",
            f"Malformed Retry-After header type: {type(raw_value).__name__}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    cleaned = raw_value.strip()
    if not cleaned:
        raise CollectorError(
            "FAILED_INVALID_RETRY_AFTER",
            "Empty Retry-After header rejected.",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    if _POSITIVE_NUMBER_RE.fullmatch(cleaned):
        delay = float(cleaned)
        if not math.isfinite(delay) or delay < 0.0:
            raise CollectorError(
                "FAILED_INVALID_RETRY_AFTER",
                f"Non-finite Retry-After numeric value: {cleaned!r}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        return delay
    try:
        parsed_dt = email.utils.parsedate_to_datetime(cleaned)
    except (TypeError, ValueError, OverflowError) as exc:
        raise CollectorError(
            "FAILED_INVALID_RETRY_AFTER",
            f"Invalid Retry-After value (expected non-negative number or IMF-fixdate): {cleaned!r}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        ) from exc
    if parsed_dt is None:
        raise CollectorError(
            "FAILED_INVALID_RETRY_AFTER",
            f"Unparseable Retry-After HTTP-date: {cleaned!r}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    if parsed_dt.tzinfo is None:
        dt_utc = parsed_dt.replace(tzinfo=timezone.utc)
    else:
        dt_utc = parsed_dt.astimezone(timezone.utc)
    now_aware = now_utc.replace(tzinfo=timezone.utc) if now_utc.tzinfo is None else now_utc.astimezone(timezone.utc)
    delta_s = (dt_utc - now_aware).total_seconds()
    return max(0.0, delta_s)


def _extract_underlying_socket(stream: Any) -> Optional[Any]:
    raw_obj = getattr(stream, "fp", stream)
    for chain in (("_sock",), ("raw", "_sock")):
        cur = raw_obj
        for attr in chain:
            cur = getattr(cur, attr, None)
            if cur is None:
                break
        if cur is not None and hasattr(cur, "settimeout"):
            return cur
    return stream if hasattr(stream, "settimeout") else None


def read_stream_bounded_with_deadline(
    stream: Any,
    *,
    max_bytes: int,
    read_timeout_s: float,
    clock_fn: Callable[[], float],
    deadline_monotonic: float,
    url: str,
    sock: Optional[Any] = None,
    chunk_size: int = 65536,
) -> bytes:
    """Read stream in bounded chunks while clamping socket timeout and checking deadline per chunk."""
    target_sock = sock if sock is not None else _extract_underlying_socket(stream)
    chunks = []
    total = 0
    while True:
        remaining = deadline_monotonic - float(clock_fn())
        if remaining <= 0.0:
            raise CollectorError(
                "FAILED_TIME_BUDGET_EXCEEDED",
                f"Overall wall-time deadline exceeded reading {url} after {total} bytes.",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                bytes_received=total,
            )
        if target_sock is not None:
            target_sock.settimeout(min(read_timeout_s, remaining))
        to_read = min(chunk_size, max(1, (max_bytes - total) + 1))
        try:
            chunk = stream.read(to_read)
        except CollectorError:
            raise
        except http.client.IncompleteRead as exc:
            total += len(exc.partial or b"")
            raise CollectorError(
                "FAILED_HTTP_TRANSPORT",
                f"Incomplete HTTP response reading {url}: {exc}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                bytes_received=total,
            ) from exc
        except (TimeoutError, OSError, http.client.HTTPException) as exc:
            if float(clock_fn()) >= deadline_monotonic:
                raise CollectorError(
                    "FAILED_TIME_BUDGET_EXCEEDED",
                    f"Read timed out past overall wall-time deadline for {url} after {total} bytes: {exc}",
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                    bytes_received=total,
                ) from exc
            raise CollectorError(
                "FAILED_HTTP_TRANSPORT",
                f"HTTP stream read error for {url} after {total} bytes: {exc}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                bytes_received=total,
            ) from exc

        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise CollectorError(
                "FAILED_RESPONSE_BYTE_LIMIT_EXCEEDED",
                f"Response exceeded max_single_response_bytes={max_bytes} for {url}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                bytes_received=total,
            )
        if float(clock_fn()) > deadline_monotonic:
            raise CollectorError(
                "FAILED_TIME_BUDGET_EXCEEDED",
                f"Late-arriving response chunk exceeded overall wall-time deadline for {url} after {total} bytes.",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                bytes_received=total,
            )
        chunks.append(chunk)
    return b"".join(chunks)


def build_stdlib_https_transport(
    url_validator: UrlValidatorCallable,
    *,
    clock_fn: Optional[Callable[[], float]] = None,
    remaining_wall_fn: Optional[Callable[[], float]] = None,
    opener_factory: Optional[Callable[[float, float, ssl.SSLContext, float], urllib.request.OpenerDirector]] = None,
) -> TransportCallable:
    """Create a cross-platform stdlib HTTPS transport with no redirects, chunk deadline, and byte limits."""
    clk = clock_fn or time.monotonic

    def _transport(
        url: str,
        connect_timeout_s: float,
        read_timeout_s: float,
        max_bytes: int,
        allowed_hosts: Tuple[str, ...],
    ) -> HttpResponse:
        del allowed_hosts
        url_validator(url)
        now_m = float(clk())
        overall_remaining = float(remaining_wall_fn()) if remaining_wall_fn is not None else max(connect_timeout_s, read_timeout_s)
        if overall_remaining <= 0.0:
            raise CollectorError(
                "FAILED_TIME_BUDGET_EXCEEDED",
                f"No remaining wall-time budget before starting HTTPS request to {url}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        deadline_m = now_m + overall_remaining
        eff_connect = min(connect_timeout_s, overall_remaining)
        eff_read = min(read_timeout_s, overall_remaining)

        ctx = ssl.create_default_context()
        if opener_factory is not None:
            opener = opener_factory(eff_connect, eff_read, ctx, deadline_m)
        else:
            opener = urllib.request.build_opener(
                _NoRedirectHandler(),
                _SplitTimeoutHTTPSHandler(
                    connect_timeout=eff_connect,
                    read_timeout=eff_read,
                    clock_fn=clk,
                    deadline_monotonic=deadline_m,
                    context=ctx,
                ),
            )
        headers = {"User-Agent": f"CloudMarketDataCollector/{COLLECTOR_VERSION}"}
        for h_key in headers:
            if h_key.lower() in FORBIDDEN_AUTH_HEADERS:
                raise CollectorError(
                    "BLOCKED_CREDENTIALS_IN_HEADER",
                    f"Forbidden credential header '{h_key}' rejected.",
                    EXIT_POLICY_REJECTED,
                )
        req = urllib.request.Request(url, method="GET", headers=headers)

        try:
            with opener.open(req) as resp:
                final_url = resp.geturl()
                url_validator(final_url)
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                body = read_stream_bounded_with_deadline(
                    resp,
                    max_bytes=max_bytes,
                    read_timeout_s=eff_read,
                    clock_fn=clk,
                    deadline_monotonic=deadline_m,
                    url=url,
                )
                return HttpResponse(
                    status=int(getattr(resp, "status", 200)),
                    headers=resp_headers,
                    body=body,
                    final_url=final_url,
                )
        except urllib.error.HTTPError as exc:
            try:
                final_url = exc.geturl() or url
                resp_headers = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
                body = (
                    read_stream_bounded_with_deadline(
                        exc,
                        max_bytes=max_bytes,
                        read_timeout_s=eff_read,
                        clock_fn=clk,
                        deadline_monotonic=deadline_m,
                        url=url,
                    )
                    if exc.fp is not None
                    else b""
                )
                return HttpResponse(
                    status=int(exc.code),
                    headers=resp_headers,
                    body=body,
                    final_url=final_url,
                )
            finally:
                exc.close()
        except CollectorError:
            raise
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, CollectorError):
                raise exc.reason
            if float(clk()) >= deadline_m:
                raise CollectorError(
                    "FAILED_TIME_BUDGET_EXCEEDED",
                    f"HTTPS request exceeded overall wall-time deadline for {url}: {exc}",
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                ) from exc
            raise CollectorError(
                "FAILED_HTTP_TRANSPORT",
                f"HTTPS transport failure for {url}: {exc}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            ) from exc
        except (http.client.HTTPException, TimeoutError, ssl.SSLError, OSError, ValueError) as exc:
            if float(clk()) >= deadline_m:
                raise CollectorError(
                    "FAILED_TIME_BUDGET_EXCEEDED",
                    f"HTTPS request exceeded overall wall-time deadline for {url}: {exc}",
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                ) from exc
            raise CollectorError(
                "FAILED_HTTP_TRANSPORT",
                f"HTTPS transport failure for {url}: {exc}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            ) from exc

    return _transport


def forbidden_network_transport(
    url: str,
    _connect_timeout_s: float,
    _read_timeout_s: float,
    _max_bytes: int,
    _allowed_hosts: Tuple[str, ...],
) -> HttpResponse:
    """Transport stub that fails immediately if any network attempt occurs during offline preflight."""
    raise CollectorError(
        "BLOCKED_NETWORK_DURING_OFFLINE_COMMAND",
        f"Network request attempted during offline preflight/verify: {url}",
        EXIT_POLICY_REJECTED,
    )


@dataclass
class BudgetTracker:
    """Mutable session & cumulative runtime consumption counters persisted into checkpoint/manifest."""

    http_requests_attempted: int = 0
    http_requests_succeeded: int = 0
    retry_count: int = 0
    total_sleep_seconds: float = 0.0
    compressed_bytes_downloaded: int = 0
    uncompressed_bytes_extracted: int = 0
    max_observed_used_weight_1m: int = 0
    last_observed_used_weight_1m: int = 0
    weight_limit_cooldown_events: int = 0
    started_monotonic: Optional[float] = None
    elapsed_wall_seconds: float = 0.0
    status_code_counts: Dict[str, int] = field(default_factory=dict)
    funding_request_timestamps: Deque[float] = field(default_factory=deque)
    host_weight_cooldown_until: Dict[str, Tuple[float, int]] = field(default_factory=dict)
    host_weight_recovery_pending: Dict[str, bool] = field(default_factory=dict)
    prior_http_requests_attempted: int = 0
    prior_http_requests_succeeded: int = 0
    prior_retry_count: int = 0
    prior_total_sleep_seconds: float = 0.0
    prior_compressed_bytes_downloaded: int = 0
    prior_uncompressed_bytes_extracted: int = 0
    prior_elapsed_wall_seconds: float = 0.0

    @property
    def total_http_requests_attempted(self) -> int:
        return self.prior_http_requests_attempted + self.http_requests_attempted

    @property
    def total_http_requests_succeeded(self) -> int:
        return self.prior_http_requests_succeeded + self.http_requests_succeeded

    @property
    def total_retry_count(self) -> int:
        return self.prior_retry_count + self.retry_count

    @property
    def total_sleep_seconds_cumulative(self) -> float:
        return round(self.prior_total_sleep_seconds + self.total_sleep_seconds, 6)

    @property
    def total_compressed_bytes_downloaded(self) -> int:
        return self.prior_compressed_bytes_downloaded + self.compressed_bytes_downloaded

    @property
    def total_uncompressed_bytes_extracted(self) -> int:
        return self.prior_uncompressed_bytes_extracted + self.uncompressed_bytes_extracted

    @property
    def total_elapsed_wall_seconds(self) -> float:
        return round(self.prior_elapsed_wall_seconds + self.elapsed_wall_seconds, 6)


class RateLimitedClient:
    """Pre-transport URL guard, rate-limit throttle, finite retry, and budget-enforcing client."""

    def __init__(
        self,
        config: CollectorConfig,
        transport: Optional[TransportCallable] = None,
        *,
        clock_fn: Optional[Callable[[], float]] = None,
        sleep_fn: Optional[Callable[[float], None]] = None,
        utc_now_fn: Optional[Callable[[], datetime]] = None,
        tracker: Optional[BudgetTracker] = None,
        on_budget_update: Optional[Callable[[], None]] = None,
    ) -> None:
        self.config = config
        self.clock_fn = clock_fn or time.monotonic
        self.sleep_fn = sleep_fn or time.sleep
        self.utc_now_fn = utc_now_fn or (lambda: datetime.now(timezone.utc))
        self.tracker = tracker or BudgetTracker()
        self.on_budget_update = on_budget_update
        if self.tracker.started_monotonic is None:
            self.tracker.started_monotonic = float(self.clock_fn())
        self._url_validator: UrlValidatorCallable = lambda u: validate_request_url(
            u,
            allowed_hosts=config.allowed_hosts,
            allowed_symbols=config.allowed_symbols,
            allowed_start_ms=config.allowed_start_ms,
            oos_forbidden_start_ms=config.oos_forbidden_start_ms,
        )
        self.transport: TransportCallable = transport or build_stdlib_https_transport(
            self._url_validator,
            clock_fn=self.clock_fn,
            remaining_wall_fn=lambda: self.remaining_wall_seconds(require_positive=True),
        )

    def _persist_consumption(self) -> None:
        if self.tracker.started_monotonic is not None:
            self.tracker.elapsed_wall_seconds = max(
                self.tracker.elapsed_wall_seconds,
                max(0.0, float(self.clock_fn()) - self.tracker.started_monotonic),
            )
        if self.on_budget_update is not None:
            self.on_budget_update()

    def check_time_budget(self) -> float:
        """Update wall-clock elapsed duration and fail closed if max_wall_time_seconds is exceeded."""
        assert self.tracker.started_monotonic is not None
        elapsed = max(0.0, float(self.clock_fn()) - self.tracker.started_monotonic)
        self.tracker.elapsed_wall_seconds = elapsed
        if elapsed > self.config.max_wall_time_seconds:
            raise CollectorError(
                "FAILED_TIME_BUDGET_EXCEEDED",
                f"Wall-time budget exhausted ({elapsed:.3f}s > {self.config.max_wall_time_seconds:.3f}s).",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        return elapsed

    def remaining_wall_seconds(self, *, require_positive: bool = False) -> float:
        """Return remaining wall-time budget in seconds, optionally failing if <= 0."""
        elapsed = self.check_time_budget()
        remaining = max(0.0, self.config.max_wall_time_seconds - elapsed)
        if require_positive and remaining <= 0.0:
            raise CollectorError(
                "FAILED_TIME_BUDGET_EXCEEDED",
                f"Wall-time budget exhausted ({elapsed:.3f}s >= {self.config.max_wall_time_seconds:.3f}s).",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
        return remaining

    def _sleep(self, seconds: float) -> None:
        if seconds > 0:
            elapsed = self.check_time_budget()
            if elapsed + seconds > self.config.max_wall_time_seconds:
                raise CollectorError(
                    "FAILED_TIME_BUDGET_EXCEEDED",
                    (
                        f"Planned wait ({elapsed:.3f}s + {seconds:.3f}s) exceeds "
                        f"max_wall_time_seconds={self.config.max_wall_time_seconds:.3f}s."
                    ),
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                )
            self.sleep_fn(seconds)
            self.tracker.total_sleep_seconds += seconds
            self.check_time_budget()

    def _compute_minute_window_reset_wait_s(self, hdrs_lower: Dict[str, str]) -> float:
        ref_dt: Optional[datetime] = None
        date_hdr = hdrs_lower.get("date", "").strip()
        if date_hdr:
            try:
                parsed = email.utils.parsedate_to_datetime(date_hdr)
                if parsed is not None:
                    ref_dt = parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
            except (TypeError, ValueError, OverflowError):
                ref_dt = None
        if ref_dt is None:
            now_dt = self.utc_now_fn()
            ref_dt = now_dt.replace(tzinfo=timezone.utc) if now_dt.tzinfo is None else now_dt.astimezone(timezone.utc)
        elapsed_in_minute = ref_dt.second + (ref_dt.microsecond / 1_000_000.0)
        return (60.0 - elapsed_in_minute) + 1.0

    def _enforce_weight_limit_gate(self, host: str) -> None:
        if host not in self.tracker.host_weight_cooldown_until:
            return
        until_mono, obs_w = self.tracker.host_weight_cooldown_until[host]
        wait_s = until_mono - float(self.clock_fn())
        if wait_s > 0.0:
            if wait_s > self.config.max_retry_after_seconds:
                raise CollectorError(
                    "FAILED_EXCHANGE_WEIGHT_LIMIT_REACHED",
                    (
                        f"Exchange 1m weight limit reached ({obs_w}/{self.config.max_used_weight_1m}); "
                        f"required window-reset wait {wait_s:.3f}s exceeds max_retry_after_seconds="
                        f"{self.config.max_retry_after_seconds:.3f}s; aborting before next request."
                    ),
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                )
            rem_wall = self.remaining_wall_seconds(require_positive=True)
            if wait_s > rem_wall:
                raise CollectorError(
                    "FAILED_EXCHANGE_WEIGHT_LIMIT_REACHED",
                    (
                        f"Exchange 1m weight limit reached ({obs_w}/{self.config.max_used_weight_1m}); "
                        f"required window-reset wait {wait_s:.3f}s exceeds remaining wall time {rem_wall:.3f}s; "
                        "aborting before next request."
                    ),
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                )
            before_mono = float(self.clock_fn())
            self._sleep(wait_s)
            after_mono = float(self.clock_fn())
            if (after_mono - before_mono) + 1e-6 < wait_s:
                raise CollectorError(
                    "FAILED_EXCHANGE_WEIGHT_LIMIT_REACHED",
                    (
                        f"Exchange weight cooldown clock verification failed "
                        f"(waited {after_mono - before_mono:.3f}s < required {wait_s:.3f}s)."
                    ),
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                )
            self.tracker.weight_limit_cooldown_events += 1
        del self.tracker.host_weight_cooldown_until[host]
        self.tracker.host_weight_recovery_pending[host] = True
        self._persist_consumption()

    def _enforce_funding_window(self) -> None:
        window_s = 300.0
        now = self.clock_fn()
        q = self.tracker.funding_request_timestamps
        while q and (now - q[0]) >= window_s:
            q.popleft()
        if len(q) >= self.config.max_funding_requests_per_5min:
            wait_s = (window_s - (now - q[0])) + 0.05
            self._sleep(wait_s)
            after = self.clock_fn()
            if after <= now:
                # Non-advancing test clock: retire oldest entry after recording sleep.
                q.popleft()
            else:
                while q and (after - q[0]) >= window_s:
                    q.popleft()
        q.append(self.clock_fn())

    def get(self, url: str, *, rate_bucket: str = "default", allow_404: bool = False) -> HttpResponse:
        """Fetch an allowlisted HTTPS URL with strict cumulative budgets, deadlines, weight gates, and Retry-After."""
        parsed = self._url_validator(url)
        host = (parsed.hostname or "").lower()
        attempt = 0
        while True:
            self.remaining_wall_seconds(require_positive=True)
            if self.tracker.total_http_requests_attempted >= self.config.max_http_requests:
                raise CollectorError(
                    "FAILED_HTTP_BUDGET_EXHAUSTED",
                    (
                        f"Cumulative HTTP request budget exhausted "
                        f"({self.tracker.total_http_requests_attempted}/{self.config.max_http_requests})."
                    ),
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                )
            remaining_bytes = self.config.max_compressed_download_bytes - self.tracker.total_compressed_bytes_downloaded
            if remaining_bytes <= 0:
                raise CollectorError(
                    "FAILED_DOWNLOAD_BYTE_BUDGET_EXHAUSTED",
                    (
                        f"Cumulative compressed download budget exhausted "
                        f"({self.tracker.total_compressed_bytes_downloaded}/{self.config.max_compressed_download_bytes})."
                    ),
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                )
            effective_max_bytes = min(self.config.max_single_response_bytes, remaining_bytes)

            self._enforce_weight_limit_gate(host)
            if rate_bucket == "funding" or host == "fapi.binance.com":
                if parsed.path in {"/fapi/v1/fundingRate", "/fapi/v1/fundingInfo"}:
                    self._enforce_funding_window()

            remaining_wall = self.remaining_wall_seconds(require_positive=True)
            eff_connect = min(self.config.connect_timeout_seconds, remaining_wall)
            eff_read = min(self.config.read_timeout_seconds, remaining_wall)

            # Persist attempted request count BEFORE transport call so crash recovery cannot reset it.
            self.tracker.http_requests_attempted += 1
            self._persist_consumption()

            transient_error: Optional[str] = None
            resp: Optional[HttpResponse] = None
            try:
                resp = self.transport(
                    url,
                    eff_connect,
                    eff_read,
                    effective_max_bytes,
                    self.config.allowed_hosts,
                )
            except CollectorError as exc:
                if exc.bytes_received > 0:
                    self.tracker.compressed_bytes_downloaded += exc.bytes_received
                self._persist_consumption()
                if self.tracker.total_compressed_bytes_downloaded > self.config.max_compressed_download_bytes:
                    raise CollectorError(
                        "FAILED_DOWNLOAD_BYTE_BUDGET_EXHAUSTED",
                        (
                            f"Cumulative compressed bytes {self.tracker.total_compressed_bytes_downloaded} "
                            f"> budget {self.config.max_compressed_download_bytes}"
                        ),
                        EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                    ) from exc
                if exc.code == "FAILED_HTTP_TRANSPORT":
                    self.check_time_budget()
                    if self.tracker.total_compressed_bytes_downloaded >= self.config.max_compressed_download_bytes:
                        raise CollectorError(
                            "FAILED_DOWNLOAD_BYTE_BUDGET_EXHAUSTED",
                            (
                                f"Cumulative compressed download budget exhausted "
                                f"({self.tracker.total_compressed_bytes_downloaded}/{self.config.max_compressed_download_bytes})."
                            ),
                            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                        ) from exc
                    transient_error = exc.message
                else:
                    raise

            if resp is not None:
                status_key = str(resp.status)
                self.tracker.status_code_counts[status_key] = self.tracker.status_code_counts.get(status_key, 0) + 1
                self.tracker.compressed_bytes_downloaded += len(resp.body)

                hdrs_lower = {str(k).lower(): str(v) for k, v in resp.headers.items()}
                used_weight_raw = hdrs_lower.get("x-mbx-used-weight-1m")
                observed_weight: Optional[int] = None
                if used_weight_raw and used_weight_raw.strip().isdigit():
                    observed_weight = int(used_weight_raw.strip())
                    self.tracker.last_observed_used_weight_1m = observed_weight
                    if observed_weight > self.tracker.max_observed_used_weight_1m:
                        self.tracker.max_observed_used_weight_1m = observed_weight

                self._persist_consumption()

                if self.tracker.total_compressed_bytes_downloaded > self.config.max_compressed_download_bytes:
                    raise CollectorError(
                        "FAILED_DOWNLOAD_BYTE_BUDGET_EXHAUSTED",
                        (
                            f"Cumulative compressed bytes {self.tracker.total_compressed_bytes_downloaded} "
                            f"> budget {self.config.max_compressed_download_bytes}"
                        ),
                        EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                    )

                if resp.final_url:
                    self._url_validator(resp.final_url)
                if 300 <= resp.status < 400:
                    raise CollectorError(
                        "BLOCKED_HTTP_REDIRECT",
                        f"HTTP {resp.status} redirect to {hdrs_lower.get('location', '')!r} rejected for {url}; redirects are prohibited.",
                        EXIT_POLICY_REJECTED,
                    )
                if resp.final_url and resp.final_url != url:
                    raise CollectorError(
                        "BLOCKED_HTTP_REDIRECT",
                        f"Silent HTTP redirect from {url} to {resp.final_url} rejected; redirects are prohibited.",
                        EXIT_POLICY_REJECTED,
                    )

                if resp.status == 200 or (resp.status == 404 and allow_404):
                    if resp.status == 200:
                        self.tracker.http_requests_succeeded += 1
                    self.check_time_budget()
                    if observed_weight is not None:
                        if observed_weight >= self.config.max_used_weight_1m:
                            if self.tracker.host_weight_recovery_pending.get(host, False):
                                self._persist_consumption()
                                raise CollectorError(
                                    "FAILED_EXCHANGE_WEIGHT_LIMIT_NOT_RECOVERED",
                                    (
                                        f"Exchange 1m weight limit did not recover after cooldown "
                                        f"({observed_weight}/{self.config.max_used_weight_1m}) for {host}."
                                    ),
                                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                                )
                            reset_wait_s = self._compute_minute_window_reset_wait_s(hdrs_lower)
                            self.tracker.host_weight_cooldown_until[host] = (
                                float(self.clock_fn()) + reset_wait_s,
                                observed_weight,
                            )
                        else:
                            self.tracker.host_weight_recovery_pending[host] = False
                    self._persist_consumption()
                    return resp

                if resp.status == 418:
                    raise CollectorError(
                        "FAILED_IP_BAN_418",
                        f"Binance HTTP 418 IP ban received for {url}; aborting immediately without retry.",
                        EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                    )

                if resp.status == 429 or (resp.status == 503 and "retry-after" in hdrs_lower):
                    if attempt >= self.config.max_retries:
                        if resp.status == 429:
                            raise CollectorError(
                                "FAILED_RATE_LIMIT_EXHAUSTED",
                                f"HTTP 429 rate limit exhausted after {attempt} retries for {url}",
                                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                            )
                        raise CollectorError(
                            "FAILED_SERVER_ERROR_EXHAUSTED",
                            f"HTTP {resp.status} exhausted after {attempt} retries for {url}",
                            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                        )
                    if "retry-after" in hdrs_lower:
                        delay_s = parse_retry_after_header(
                            hdrs_lower["retry-after"],
                            now_utc=self.utc_now_fn(),
                        )
                        if delay_s > self.config.max_retry_after_seconds:
                            raise CollectorError(
                                "FAILED_RETRY_AFTER_EXCEEDS_MAX_WAIT",
                                (
                                    f"Server Retry-After={delay_s:.3f}s exceeds configured "
                                    f"max_retry_after_seconds={self.config.max_retry_after_seconds:.3f}s for {url}; "
                                    "refusing to shorten server wait."
                                ),
                                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                            )
                        rem_wall = self.remaining_wall_seconds(require_positive=False)
                        if delay_s > rem_wall:
                            raise CollectorError(
                                "FAILED_RETRY_AFTER_EXCEEDS_REMAINING_TIME",
                                (
                                    f"Server Retry-After={delay_s:.3f}s exceeds remaining wall-time budget "
                                    f"{rem_wall:.3f}s for {url}; aborting without early retry."
                                ),
                                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                            )
                        wait_s = delay_s
                    else:
                        wait_s = min(
                            self.config.retry_backoff_base_seconds * (2 ** attempt),
                            self.config.retry_backoff_max_seconds,
                        )
                    self.tracker.retry_count += 1
                    attempt += 1
                    self._persist_consumption()
                    self._sleep(wait_s)
                    continue

                if 500 <= resp.status < 600:
                    if attempt >= self.config.max_retries:
                        raise CollectorError(
                            "FAILED_SERVER_ERROR_EXHAUSTED",
                            f"HTTP {resp.status} exhausted after {attempt} retries for {url}",
                            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                        )
                    wait_s = min(
                        self.config.retry_backoff_base_seconds * (2 ** attempt),
                        self.config.retry_backoff_max_seconds,
                    )
                    self.tracker.retry_count += 1
                    attempt += 1
                    self._persist_consumption()
                    self._sleep(wait_s)
                    continue

                raise CollectorError(
                    "FAILED_HTTP_CLIENT_ERROR",
                    f"Non-retryable HTTP status {resp.status} for {url}",
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                )

            # Transient transport error
            if attempt >= self.config.max_retries:
                raise CollectorError(
                    "FAILED_NETWORK_RETRIES_EXHAUSTED",
                    f"Transport failed after {attempt} retries for {url}: {transient_error}",
                    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
                )
            wait_s = min(
                self.config.retry_backoff_base_seconds * (2 ** attempt),
                self.config.retry_backoff_max_seconds,
            )
            self.tracker.retry_count += 1
            attempt += 1
            self._persist_consumption()
            self._sleep(wait_s)
