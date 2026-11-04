"""Markdown runbook loader (YAML front matter + ``##`` sections).

Runbooks are the RAG knowledge base, so they are a poisoning target (OWASP LLM04/LLM08):
files are size-limited, metadata is schema-validated, every file is hashed (hashes are
written to the audit log at startup) and the body is scanned with the same prompt-injection
detector used for alerts. Suspicious runbooks are rejected, not indexed.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from ..models import Severity, normalize_technique_id
from ..security.injection import scan_for_injection

logger = logging.getLogger(__name__)

MAX_RUNBOOK_BYTES = 64 * 1024
_FRONT_MATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n(.*)\Z", re.DOTALL)
_LIST_ITEM_RE = re.compile(r"^\s*(?:\d+[.)]|[-*])\s+(.+)$")


class RunbookMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    title: str = Field(min_length=3, max_length=160)
    mitre: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    wazuh_groups: list[str] = Field(default_factory=list)
    wazuh_rules: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    severity_hint: Severity | None = None

    @field_validator("mitre")
    @classmethod
    def _check_mitre(cls, values: list[str]) -> list[str]:
        normalized = [normalize_technique_id(v) for v in values]
        if any(v is None for v in normalized):
            raise ValueError("invalid MITRE technique id in runbook metadata")
        return [v for v in normalized if v]

    @field_validator("wazuh_rules", "keywords", "wazuh_groups", "tactics", mode="before")
    @classmethod
    def _scalars_as_str(cls, values: object) -> object:
        if isinstance(values, list):
            return [str(v) if isinstance(v, int | float) else v for v in values]
        return values


@dataclass(frozen=True)
class RunbookSection:
    runbook_id: str
    title: str
    text: str

    def list_items(self) -> list[str]:
        return [m.group(1).strip() for line in self.text.splitlines() if (m := _LIST_ITEM_RE.match(line))]


@dataclass(frozen=True)
class Runbook:
    meta: RunbookMeta
    sections: tuple[RunbookSection, ...]
    sha256: str
    path: str

    @property
    def id(self) -> str:
        return self.meta.id


@dataclass
class RunbookLoadResult:
    runbooks: list[Runbook] = field(default_factory=list)
    rejected: dict[str, str] = field(default_factory=dict)


def _split_sections(runbook_id: str, body: str) -> tuple[RunbookSection, ...]:
    sections: list[RunbookSection] = []
    title = "Overview"
    buffer: list[str] = []
    for line in body.splitlines():
        if line.startswith("## "):
            if "".join(buffer).strip():
                sections.append(RunbookSection(runbook_id, title, "\n".join(buffer).strip()))
            title, buffer = line[3:].strip(), []
        elif line.startswith("# "):
            continue  # document title duplicates metadata
        else:
            buffer.append(line)
    if "".join(buffer).strip():
        sections.append(RunbookSection(runbook_id, title, "\n".join(buffer).strip()))
    return tuple(sections)


def parse_runbook(path: Path, *, injection_threshold: int = 3) -> Runbook:
    raw = path.read_bytes()
    if len(raw) > MAX_RUNBOOK_BYTES:
        raise ValueError(f"file larger than {MAX_RUNBOOK_BYTES} bytes")
    text = raw.decode("utf-8")
    match = _FRONT_MATTER_RE.match(text)
    if not match:
        raise ValueError("missing YAML front matter")
    front = yaml.safe_load(match.group(1)) or {}
    if not isinstance(front, dict):
        raise ValueError("front matter must be a mapping")
    try:
        meta = RunbookMeta.model_validate(front)
    except ValidationError as exc:
        raise ValueError(f"invalid metadata: {exc.error_count()} error(s)") from None
    body = match.group(2)
    report = scan_for_injection({"meta": front, "body": body}, threshold=injection_threshold)
    if report.suspected:
        raise ValueError(f"prompt-injection content detected ({', '.join(report.indicators[:3])})")
    sections = _split_sections(meta.id, body)
    if not sections:
        raise ValueError("runbook has no content")
    return Runbook(meta=meta, sections=sections, sha256=hashlib.sha256(raw).hexdigest(), path=path.name)


def load_runbooks(directory: Path, *, injection_threshold: int = 3) -> RunbookLoadResult:
    result = RunbookLoadResult()
    if not directory.is_dir():
        logger.warning("runbooks directory %s does not exist; RAG disabled", directory)
        return result
    seen: set[str] = set()
    for path in sorted(directory.glob("*.md")):
        if path.is_symlink() or not path.is_file():
            result.rejected[path.name] = "not a regular file"
            continue
        try:
            runbook = parse_runbook(path, injection_threshold=injection_threshold)
        except (ValueError, UnicodeDecodeError, yaml.YAMLError) as exc:
            result.rejected[path.name] = str(exc)
            logger.error("rejected runbook %s: %s", path.name, exc)
            continue
        if runbook.id in seen:
            result.rejected[path.name] = f"duplicate runbook id {runbook.id}"
            continue
        seen.add(runbook.id)
        result.runbooks.append(runbook)
    return result
