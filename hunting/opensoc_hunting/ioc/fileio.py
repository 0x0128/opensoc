"""Reading/writing IOC files detecting the format (STIX 2.1 JSON or CSV)."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .csv_io import dumps_csv, read_csv
from .model import IOC
from .stix import from_stix, to_stix_bundle

FORMATS = ("stix", "csv")


@dataclass
class LoadResult:
    iocs: list[IOC] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    format: str = ""


def guess_format(path: str, text: str | None = None) -> str:
    suffix = Path(path).suffix.lower()
    if suffix in {".json", ".stix", ".stix2"}:
        return "stix"
    if suffix in {".csv", ".txt"}:
        return "csv"
    if text is not None and text.lstrip().startswith(("{", "[")):
        return "stix"
    return "csv"


def _read_text(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8-sig")


def load_iocs(path: str, fmt: str = "auto") -> LoadResult:
    text = _read_text(path)
    fmt = guess_format(path, text) if fmt == "auto" else fmt
    result = LoadResult(format=fmt)
    if fmt == "stix":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            result.errors.append(f"invalid JSON: {exc}")
            return result
        report = from_stix(data)
    elif fmt == "csv":
        report = read_csv(text)
    else:
        raise ValueError(f"unknown format: {fmt}")
    result.iocs, result.warnings, result.errors = report.iocs, report.warnings, report.errors
    return result


def render_iocs(iocs: Iterable[IOC], fmt: str, *, producer: str = "OpenSOC Lab", defanged: bool = False) -> str:
    if fmt == "stix":
        return json.dumps(to_stix_bundle(iocs, producer=producer), indent=2, ensure_ascii=False) + "\n"
    if fmt == "csv":
        return dumps_csv(iocs, defanged=defanged)
    raise ValueError(f"unknown format: {fmt}")


def save_iocs(iocs: Iterable[IOC], path: str, fmt: str = "auto", **kwargs) -> str:
    fmt = guess_format(path) if fmt == "auto" else fmt
    content = render_iocs(iocs, fmt, **kwargs)
    if path == "-":
        sys.stdout.write(content)
    else:
        Path(path).write_text(content, encoding="utf-8")
    return fmt
