"""Helpers for MITRE ATT&CK identifiers."""

from __future__ import annotations

import re

TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
# Finds IDs inside free text: "T1003.001", "attack.t1003.001", "<id>T1059</id>"...
TECHNIQUE_IN_TEXT_RE = re.compile(r"(?<![A-Za-z0-9])[Tt](\d{4}(?:\.\d{3})?)(?![0-9])")


def is_technique(value: str) -> bool:
    return bool(TECHNIQUE_RE.match(value or ""))


def normalize_technique(value: str) -> str:
    """Returns the upper-case ID ("t1003.001" -> "T1003.001") or raises ValueError."""
    candidate = (value or "").strip().upper()
    if candidate.startswith("ATTACK."):
        candidate = candidate[len("ATTACK."):]
    if not is_technique(candidate):
        raise ValueError(f"invalid ATT&CK technique ID: {value!r}")
    return candidate


def parent_technique(value: str) -> str:
    """T1003.001 -> T1003; T1003 -> T1003."""
    return normalize_technique(value).split(".", 1)[0]


def find_techniques(text: str) -> list[str]:
    """Extracts technique IDs from a text, without duplicates and in order of appearance."""
    seen: dict[str, None] = {}
    for match in TECHNIQUE_IN_TEXT_RE.finditer(text or ""):
        seen.setdefault("T" + match.group(1), None)
    return list(seen)
