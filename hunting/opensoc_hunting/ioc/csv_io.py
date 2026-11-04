"""Reading and writing IOCs as CSV.

Columns: type,value,description,tags,tlp,confidence,first_seen,source,to_ids
Only ``value`` is required; if ``type`` is missing it is inferred from the value. Tags are
separated with ``;``. On export, formula injection (cells that start
with = + - @) is neutralized by prepending a single quote, which is removed on import.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TextIO

from .model import IOC, IOCError, defang, detect_type

COLUMNS = ["type", "value", "description", "tags", "tlp", "confidence", "first_seen", "source", "to_ids"]
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_TRUE = {"1", "true", "yes", "y", "si", "sí", "x"}
_FALSE = {"0", "false", "no", "n"}


@dataclass
class ParseReport:
    iocs: list[IOC] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _protect(cell: str) -> str:
    return "'" + cell if cell.startswith(_FORMULA_PREFIXES) else cell


def _unprotect(cell: str) -> str:
    if len(cell) > 1 and cell[0] == "'" and cell[1] in "=+-@\t\r":
        return cell[1:]
    return cell


def _parse_bool(value: str, default: bool = True) -> bool:
    text = (value or "").strip().lower()
    if not text:
        return default
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise IOCError(f"invalid to_ids: {value!r}")


def read_csv(source: TextIO | str) -> ParseReport:
    """Reads IOCs from an open file or from the CSV text."""
    fh = io.StringIO(source) if isinstance(source, str) else source
    text = fh.read()
    if text.startswith("﻿"):
        text = text[1:]
    report = ParseReport()
    if not text.strip():
        report.errors.append("empty CSV")
        return report

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        report.errors.append("CSV without a header")
        return report
    header = {name: (name or "").strip().lower() for name in reader.fieldnames}
    if "value" not in header.values():
        report.errors.append("the required 'value' column is missing")
        return report
    unknown = sorted(set(header.values()) - set(COLUMNS) - {""})
    if unknown:
        report.warnings.append(f"ignored columns: {', '.join(unknown)}")

    for line_no, row in enumerate(reader, start=2):
        data = {header[k]: _unprotect((v or "").strip()) for k, v in row.items() if k is not None}
        if not any(data.values()):
            continue
        value = data.get("value", "")
        if not value or value.startswith("#"):
            continue
        try:
            ioc_type = data.get("type") or detect_type(value)
            report.iocs.append(
                IOC(
                    type=ioc_type,
                    value=value,
                    description=data.get("description", ""),
                    tags=[t for t in data.get("tags", "").split(";")],
                    tlp=data.get("tlp") or None,
                    confidence=data.get("confidence") or None,
                    first_seen=data.get("first_seen") or None,
                    source=data.get("source", ""),
                    to_ids=_parse_bool(data.get("to_ids", "")),
                )
            )
        except IOCError as exc:
            report.errors.append(f"line {line_no}: {exc}")
    return report


def write_csv(iocs: Iterable[IOC], fh: TextIO, *, defanged: bool = False) -> int:
    writer = csv.writer(fh, lineterminator="\n")
    writer.writerow(COLUMNS)
    count = 0
    for ioc in iocs:
        row = [
            ioc.type,
            defang(ioc.type, ioc.value) if defanged else ioc.value,
            ioc.description,
            ";".join(ioc.tags),
            ioc.tlp or "",
            "" if ioc.confidence is None else str(ioc.confidence),
            ioc.first_seen or "",
            ioc.source,
            "true" if ioc.to_ids else "false",
        ]
        writer.writerow([_protect(cell) for cell in row])
        count += 1
    return count


def dumps_csv(iocs: Iterable[IOC], *, defanged: bool = False) -> str:
    buffer = io.StringIO()
    write_csv(iocs, buffer, defanged=defanged)
    return buffer.getvalue()
