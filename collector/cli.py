"""Command-line interface for preflight, collect, verify, and export-bundle."""

from __future__ import annotations

import argparse
import datetime as _dt
import json
from typing import Callable, Optional, Sequence

from .constants import CollectorError
from .engine import run_collect, run_export_bundle, run_preflight, run_verify
from .transport import TransportCallable


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="collector",
        description="Binance USD-M Futures Historical Market Data Collector (Public Market Data Only)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_pre = sub.add_parser("preflight", help="Run offline config, boundary, URL, and budget validation (0 network calls).")
    p_pre.add_argument("--config", required=True, help="Path to collector JSON config file.")
    p_pre.add_argument("--out-dir", required=False, help="Optional directory to write preflight_report.json.")

    p_col = sub.add_parser("collect", help="Collect monthly public data with verification, checkpoints, and resume.")
    p_col.add_argument("--config", required=True, help="Path to collector JSON config file.")
    p_col.add_argument("--out-dir", required=True, help="Output package directory.")
    p_col.add_argument("--resume", action="store_true", help="Resume existing output directory verifying prior disk artifacts.")

    p_ver = sub.add_parser("verify", help="Verify SHA256SUMS.txt, manifest.json, POSIX paths, and OOS constraints offline.")
    p_ver.add_argument("--package-dir", required=True, help="Collected output directory containing manifest.json & SHA256SUMS.txt.")
    p_ver.add_argument("--require-complete", action="store_true", help="Also fail with exit 3 if manifest status != COMPLETE.")

    p_exp = sub.add_parser("export-bundle", help="Verify and export deterministic .tar.gz + .sha256 package.")
    p_exp.add_argument("--package-dir", required=True, help="Verified output directory.")
    p_exp.add_argument("--archive-path", required=True, help="Destination .tar.gz path.")
    p_exp.add_argument("--allow-incomplete", action="store_true", help="Permit bundling an integrity-verified INCOMPLETE package.")
    return parser


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    transport: Optional[TransportCallable] = None,
    clock_fn: Optional[Callable[[], float]] = None,
    sleep_fn: Optional[Callable[[float], None]] = None,
    utc_now_fn: Optional[Callable[[], _dt.datetime]] = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.command == "preflight":
            code, payload = run_preflight(args.config, out_dir=args.out_dir)
        elif args.command == "collect":
            code, payload = run_collect(
                args.config,
                args.out_dir,
                resume=bool(args.resume),
                transport=transport,
                clock_fn=clock_fn,
                sleep_fn=sleep_fn,
                utc_now_fn=utc_now_fn,
            )
        elif args.command == "verify":
            code, payload = run_verify(args.package_dir, require_complete=bool(args.require_complete))
        elif args.command == "export-bundle":
            code, payload = run_export_bundle(
                args.package_dir,
                args.archive_path,
                require_complete=not bool(args.allow_incomplete),
            )
        else:  # pragma: no cover
            parser.error(f"Unknown command: {args.command}")
            return 2
    except CollectorError as exc:
        code = exc.exit_code
        payload = {
            "status": "ERROR",
            "error_code": exc.code,
            "error_message": exc.message,
            "exit_code": code,
        }

    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    return code
