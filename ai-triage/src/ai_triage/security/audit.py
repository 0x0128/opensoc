"""Tamper-evident audit trail (JSON Lines, hash-chained, optional HMAC).

Every record carries ``prev`` (the previous record's hash) and ``hash`` over its canonical
JSON, so deleting, reordering or editing any line breaks the chain. With
``TRIAGE_AUDIT_HMAC_KEY`` the hash is an HMAC, so an attacker with write access to the file
cannot recompute a valid chain without the key. Records never contain raw alert content:
only identifiers, hashes, counters and the (already redacted) triage output.

Verify a file with:  ``python -m ai_triage.security.audit verify /var/log/ai-triage/audit.jsonl``
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

GENESIS = "0" * 64


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _digest(payload: str, key: bytes | None) -> str:
    if key:
        return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return sha256_hex(payload)


class AuditLogger:
    def __init__(self, destination: str | Path = "-", *, hmac_key: bytes | None = None) -> None:
        self._key = hmac_key or None
        self._lock = threading.Lock()
        self._path: Path | None = None if str(destination) == "-" else Path(destination)
        self._stream: TextIO = sys.stdout
        self._prev = GENESIS
        self._seq = 0
        if self._path is not None:
            # Fail closed: the service must not run without a working audit trail.
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                self._path.open("a", encoding="utf-8").close()
            except OSError as exc:
                raise RuntimeError(f"audit log {self._path} is not writable: {exc.strerror}") from None
            self._resume_chain()

    def _resume_chain(self) -> None:
        assert self._path is not None
        if not self._path.exists():
            return
        last_line = ""
        with self._path.open("rb") as handle:
            for line in handle:
                if line.strip():
                    last_line = line.decode("utf-8", errors="replace")
        if last_line:
            try:
                last = json.loads(last_line)
                self._prev, self._seq = str(last["hash"]), int(last["seq"])
            except (ValueError, KeyError, TypeError):
                # Corrupted tail: start a new segment that explicitly references the breakage.
                self._prev = sha256_hex(last_line)

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            self._seq += 1
            entry: dict[str, Any] = {
                "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
                "seq": self._seq,
                "event": event,
                **fields,
                "prev": self._prev,
            }
            entry["hash"] = _digest(_canonical(entry), self._key)
            line = _canonical(entry)
            if self._path is None:
                self._stream.write(line + "\n")
                self._stream.flush()
            else:
                with self._path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
            self._prev = entry["hash"]
            return entry


def verify_chain(path: str | Path, *, hmac_key: bytes | None = None) -> tuple[bool, int, str]:
    """Verify an audit file. Returns ``(ok, records_checked, message)``."""
    prev: str | None = None
    count = 0
    with Path(path).open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                claimed = entry.pop("hash")
            except (ValueError, KeyError):
                return False, count, f"line {line_no}: unparsable record"
            if prev is not None and entry.get("prev") != prev:
                return False, count, f"line {line_no}: chain broken (prev hash mismatch)"
            if not hmac.compare_digest(_digest(_canonical(entry), hmac_key), str(claimed)):
                return False, count, f"line {line_no}: record hash mismatch (modified record or wrong key)"
            prev = claimed
            count += 1
    return True, count, "ok"


def main(argv: list[str] | None = None) -> int:
    import argparse
    import os

    parser = argparse.ArgumentParser(description="Verify an ai-triage audit log hash chain")
    parser.add_argument("command", choices=["verify"])
    parser.add_argument("path")
    args = parser.parse_args(argv)
    key = os.environ.get("TRIAGE_AUDIT_HMAC_KEY", "").encode() or None
    ok, count, message = verify_chain(args.path, hmac_key=key)
    print(f"{'OK' if ok else 'FAIL'}: {count} records verified - {message}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
