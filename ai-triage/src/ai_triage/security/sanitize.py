"""Normalisation and structural limits applied to untrusted alert content."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable, Iterator
from typing import Any

# Zero-width characters, BOM and Unicode bidirectional controls ("Trojan Source").
INVISIBLE_RE = re.compile("[​-‏  ‪-‮⁠-⁤⁦-⁩﻿]")
# Unicode "tag" block, abused for ASCII smuggling of hidden instructions.
TAG_CHARS_RE = re.compile("[\U000e0000-\U000e007f]")
# C0/C1 control characters except tab and newline.
CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

TRUNCATION_MARK = "…[truncated]"


def decode_tag_chars(text: str) -> str:
    """Reveal text hidden with Unicode tag characters (U+E0020..U+E007E map to ASCII)."""
    return "".join(chr(ord(ch) - 0xE0000) for ch in TAG_CHARS_RE.findall(text) if 0x20 <= ord(ch) - 0xE0000 < 0x7F)


def normalize_text(text: str) -> str:
    """NFKC-normalise and drop invisible/control characters (keeps newlines and tabs)."""
    text = unicodedata.normalize("NFKC", text)
    text = TAG_CHARS_RE.sub("", text)
    text = INVISIBLE_RE.sub("", text)
    text = CONTROL_RE.sub("", text)
    return text.replace("\r\n", "\n").replace("\r", "\n")


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - len(TRUNCATION_MARK))] + TRUNCATION_MARK


def sanitize_structure(
    obj: Any,
    *,
    max_depth: int = 8,
    max_keys: int = 128,
    max_items: int = 64,
    max_str: int = 8192,
    _depth: int = 0,
) -> Any:
    """Return a normalised copy of ``obj`` bounded in depth, width and string length."""
    if isinstance(obj, str):
        return truncate(normalize_text(obj), max_str)
    if obj is None or isinstance(obj, bool | int | float):
        return obj
    if _depth >= max_depth:
        return TRUNCATION_MARK
    kwargs = {"max_depth": max_depth, "max_keys": max_keys, "max_items": max_items, "max_str": max_str}
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for index, (key, value) in enumerate(obj.items()):
            if index >= max_keys:
                out["_truncated_keys"] = len(obj) - max_keys
                break
            clean_key = truncate(normalize_text(str(key)), 128)
            out[clean_key] = sanitize_structure(value, _depth=_depth + 1, **kwargs)
        return out
    if isinstance(obj, list | tuple):
        items = [sanitize_structure(value, _depth=_depth + 1, **kwargs) for value in obj[:max_items]]
        if len(obj) > max_items:
            items.append(f"{TRUNCATION_MARK} {len(obj) - max_items} more items")
        return items
    return truncate(normalize_text(str(obj)), max_str)


def walk_strings(obj: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield ``(path, text)`` for every string value *and* dict key in a nested structure."""
    if isinstance(obj, str):
        yield path or "$", obj
    elif isinstance(obj, dict):
        for key, value in obj.items():
            child = f"{path}.{key}" if path else str(key)
            yield f"{child}#key", str(key)
            yield from walk_strings(value, child)
    elif isinstance(obj, list | tuple):
        for index, value in enumerate(obj):
            yield from walk_strings(value, f"{path}[{index}]")


def map_strings(obj: Any, func: Callable[[str], str]) -> Any:
    """Apply ``func`` to every string value (not keys) of a nested structure."""
    if isinstance(obj, str):
        return func(obj)
    if isinstance(obj, dict):
        return {key: map_strings(value, func) for key, value in obj.items()}
    if isinstance(obj, list):
        return [map_strings(value, func) for value in obj]
    return obj
