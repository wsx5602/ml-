"""Cross-platform disk-byte SHA-256, atomic file I/O, and safe path validation."""

from __future__ import annotations

import hashlib
import itertools
import json
import os
from pathlib import Path
from typing import Any, Tuple

from .constants import (
    EXIT_POLICY_REJECTED,
    EXIT_RUNTIME_OR_INTEGRITY_ERROR,
    FORBIDDEN_PATH_SEGMENTS,
    CollectorError,
)

_TMP_COUNTER = itertools.count(1)


def sha256_bytes_raw(data: bytes) -> str:
    """Return lowercase SHA-256 hex digest of an exact byte sequence."""
    return hashlib.sha256(data).hexdigest()


def sha256_file_from_disk(path: Path) -> Tuple[str, int]:
    """Compute SHA-256 hex digest and byte length by reading actual disk bytes in binary mode."""
    if not path.is_file():
        raise CollectorError(
            "FAILED_MISSING_FILE_FOR_HASH",
            f"Cannot hash missing file: {path}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    digest = hashlib.sha256()
    total_bytes = 0
    with path.open("rb") as fp:
        while True:
            chunk = fp.read(65536)
            if not chunk:
                break
            digest.update(chunk)
            total_bytes += len(chunk)
    return digest.hexdigest(), total_bytes


def atomic_write_bytes(
    target: Path,
    data: bytes,
    *,
    allow_overwrite: bool = False,
) -> Tuple[str, int]:
    """Atomically write raw bytes and return (disk_sha256, disk_bytes) read back from disk."""
    if not allow_overwrite and target.exists():
        raise CollectorError(
            "FAILED_IMMUTABLE_ARTIFACT_EXISTS",
            f"Refusing to overwrite immutable artifact: {target}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target.parent / f".tmp.{target.name}.{os.getpid()}.{next(_TMP_COUNTER)}"
    try:
        with tmp_path.open("wb") as fp:
            fp.write(data)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(tmp_path, target)
    except Exception:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise

    disk_sha256, disk_bytes = sha256_file_from_disk(target)
    if disk_bytes != len(data):
        raise CollectorError(
            "FAILED_POST_WRITE_BYTE_COUNT_MISMATCH",
            f"Disk size {disk_bytes} != written bytes {len(data)} for {target}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    return disk_sha256, disk_bytes


def atomic_write_utf8_lf(
    target: Path,
    text: str,
    *,
    allow_overwrite: bool = False,
) -> Tuple[str, int]:
    """Write UTF-8 LF-only text atomically and hash actual disk bytes after write."""
    if "\r" in text:
        raise CollectorError(
            "FAILED_UNEXPECTED_CR_IN_OUTPUT",
            f"Refusing to write CR characters to normalized LF output: {target}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    return atomic_write_bytes(target, text.encode("utf-8"), allow_overwrite=allow_overwrite)


def atomic_write_json(
    target: Path,
    payload: Any,
    *,
    allow_overwrite: bool = True,
) -> Tuple[str, int]:
    """Serialize canonical LF-terminated JSON atomically and return (disk_sha256, disk_bytes)."""
    serialized = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    return atomic_write_utf8_lf(target, serialized, allow_overwrite=allow_overwrite)


def _is_symlink_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction and is_junction())


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except ValueError:
        return False


def validate_safe_dir_path(raw_path: str, label: str = "path") -> Path:
    """Reject empty, traversal, symlink/junction, and forbidden OOS path segments."""
    if not raw_path or not raw_path.strip():
        raise CollectorError(
            "BLOCKED_UNSAFE_PATH",
            f"Empty {label} is not allowed.",
            EXIT_POLICY_REJECTED,
        )
    normalized_parts = raw_path.replace("\\", "/").split("/")
    if ".." in normalized_parts or "\x00" in raw_path:
        raise CollectorError(
            "BLOCKED_UNSAFE_PATH",
            f"Path traversal or NUL byte rejected in {label}: {raw_path!r}",
            EXIT_POLICY_REJECTED,
        )
    path = Path(raw_path)
    for anc in (path, *path.parents):
        if _is_symlink_or_junction(anc):
            raise CollectorError(
                "BLOCKED_UNSAFE_PATH",
                f"Symlink/junction rejected in {label}: {anc}",
                EXIT_POLICY_REJECTED,
            )
        if anc.name and anc.name.lower() in FORBIDDEN_PATH_SEGMENTS:
            raise CollectorError(
                "BLOCKED_FORBIDDEN_PATH_SEGMENT",
                f"Forbidden path segment '{anc.name}' rejected in {label}: {raw_path}",
                EXIT_POLICY_REJECTED,
            )
    resolved = path.resolve(strict=False)
    for part in resolved.parts:
        if part.lower() in FORBIDDEN_PATH_SEGMENTS:
            raise CollectorError(
                "BLOCKED_FORBIDDEN_PATH_SEGMENT",
                f"Forbidden resolved path segment '{part}' rejected in {label}: {resolved}",
                EXIT_POLICY_REJECTED,
            )
    return path


def validate_safe_input_file(raw_path: str, label: str = "input file") -> Path:
    """Validate an existing regular file with zero symlink/traversal/forbidden segments."""
    p = validate_safe_dir_path(raw_path, label=label)
    if not p.is_file():
        raise CollectorError(
            "BLOCKED_MISSING_INPUT_FILE",
            f"Missing {label}: {raw_path}",
            EXIT_POLICY_REJECTED,
        )
    return p


def to_rel_posix(path: Path, root: Path) -> str:
    """Return a clean relative POSIX path using '/' separators."""
    rel = path.resolve(strict=False).relative_to(root.resolve(strict=False))
    return rel.as_posix()


def resolve_safe_rel_posix(root: Path, rel_posix: str) -> Path:
    """Strictly resolve a relative POSIX path inside root, rejecting Windows separators or escape."""
    if (
        not rel_posix
        or "\\" in rel_posix
        or ":" in rel_posix
        or "\x00" in rel_posix
        or rel_posix.startswith("/")
    ):
        raise CollectorError(
            "FAILED_UNSAFE_RELATIVE_PATH",
            f"Invalid relative POSIX path: {rel_posix!r}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    parts = rel_posix.split("/")
    if any(not part or part in {".", ".."} or part.lower() in FORBIDDEN_PATH_SEGMENTS for part in parts):
        raise CollectorError(
            "FAILED_UNSAFE_RELATIVE_PATH",
            f"Unsafe segment in relative POSIX path: {rel_posix!r}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    resolved_root = root.resolve(strict=False)
    cur = resolved_root
    for part in parts:
        cur = cur / part
        if _is_symlink_or_junction(cur):
            raise CollectorError(
                "FAILED_UNSAFE_RELATIVE_PATH",
                f"Symlink/junction encountered resolving {rel_posix!r}: {cur}",
                EXIT_RUNTIME_OR_INTEGRITY_ERROR,
            )
    if not _is_within(cur, resolved_root):
        raise CollectorError(
            "FAILED_UNSAFE_RELATIVE_PATH",
            f"Resolved path escapes package root: {rel_posix!r}",
            EXIT_RUNTIME_OR_INTEGRITY_ERROR,
        )
    return cur


def compute_directory_bytes(root: Path) -> int:
    """Sum actual byte sizes of all regular files currently under root."""
    if not root.exists():
        return 0
    total = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dir_p = Path(dirpath)
        dirnames[:] = [d for d in dirnames if not _is_symlink_or_junction(dir_p / d)]
        for fname in filenames:
            fp = dir_p / fname
            if fp.is_file() and not _is_symlink_or_junction(fp):
                total += fp.stat().st_size
    return total
