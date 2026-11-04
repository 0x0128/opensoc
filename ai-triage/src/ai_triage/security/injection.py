"""Heuristic prompt-injection detection over untrusted alert fields (OWASP LLM01).

Detection is a *signal*, not the primary control: the structural defences (random-nonce
delimiters, JSON encoding, strict output validation and guardrails) apply to every alert.
A positive detection makes the pipeline more conservative (severity floor, confidence cap,
mandatory human review) or, with ``TRIAGE_INJECTION_POLICY=block``, skips the LLM entirely.
Findings only carry the rule name and the field path, never the matched text, so the
report can be logged without leaking PII.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import Any

from .sanitize import INVISIBLE_RE, TAG_CHARS_RE, decode_tag_chars, normalize_text, walk_strings

# Common Cyrillic/Greek homoglyphs of Latin letters (only used for scanning, never for display).
_CONFUSABLES = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ѕ": "s",
        "ј": "j", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ո": "n", "ν": "v", "ο": "o", "α": "a",
        "ε": "e", "ι": "i", "κ": "k", "τ": "t", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
        "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I",
    }
)  # fmt: skip

_I = re.IGNORECASE
_IM = re.IGNORECASE | re.MULTILINE

# (rule name, weight, compiled pattern). Weight >= threshold (default 3) flags on its own.
PATTERNS: list[tuple[str, int, re.Pattern[str]]] = [
    (
        "ignore_instructions",
        4,
        re.compile(
            r"\b(ignore|disregard|forget|override|skip)\s+(?:(?:all|any|the|your|my|of|these)\s+)*"
            r"(previous|prior|above|earlier|preceding|system|original|safety)\s+"
            r"(instructions?|prompts?|rules|directions|directives|context|messages?|guidelines)",
            _I,
        ),
    ),
    (
        "ignore_everything",
        4,
        re.compile(r"\b(ignore|disregard|forget)\s+(everything|all)\s+(above|before|previously|so far)", _I),
    ),
    (
        "ignore_instructions_es",
        4,
        re.compile(
            r"\b(ignora|ignorad|ignore|olvida|olvidad|descarta|omite|omitid)\s+(?:todas?\s+|todo\s+)?"
            r"(?:las\s+|tus\s+|sus\s+|lo\s+)?(instrucciones|reglas|indicaciones|[oó]rdenes|anterior)",
            _I,
        ),
    ),
    (
        "chat_template_tokens",
        4,
        re.compile(
            r"<\|(im_start|im_end|system|user|assistant|endoftext|begin_of_text|eot_id|start_header_id)\|>"
            r"|\[/?INST\]|<<\s*/?SYS\s*>>",
            _I,
        ),
    ),
    (
        "verdict_manipulation",
        3,
        re.compile(
            r"\b(mark|classify|label|treat|report|flag|set|rate|consider|close|dismiss)\s+"
            r"(?:(?:this|the|it|these|that|all)\s+)?(?:(?:alert|alerts|event|incident|log|activity|entry)\s+)?"
            r"(as|to)\s+(?:an?\s+)?(benign|harmless|false[\s_-]?positive|informational|"
            r"low[\s_-]?(?:severity|priority|risk)|safe|non[\s-]?malicious|expected|authori[sz]ed|resolved)",
            _I,
        ),
    ),
    (
        "verdict_manipulation_es",
        3,
        re.compile(
            r"\b(marca|marcar|clasifica|clasificar|trata|tratar|considera|considerar|cierra|cerrar)\s+"
            r"(?:(?:esta|este|la|el|esto)\s+)?(?:(?:alerta|evento|incidente|actividad)\s+)?como\s+"
            r"(benign[oa]|inofensiv[oa]|falso\s+positivo|informativ[oa]|baja|segur[oa]|autorizad[oa])",
            _I,
        ),
    ),
    (
        "addresses_ai",
        3,
        re.compile(
            r"\b(note|message|attention|instructions?|dear|hey|nota|mensaje|atenci[oó]n)[\s:,]+"
            r"(?:(?:to|for|para|al?)\s+)?"
            r"(?:the\s+|el\s+|la\s+)?(ai|a\.i\.|llm|assistant|asistente|language\s+model|chatbot|"
            r"triage\s+(?:bot|agent|model)|ia)\b",
            _I,
        ),
    ),
    (
        "role_override",
        2,
        re.compile(
            r"\b(you\s+are\s+now|from\s+now\s+on\s+you|act\s+as\s+(?:an?\s+)?(?:different|new|unrestricted)|"
            r"pretend\s+(?:to\s+be|you\s+are)|new\s+instructions|ahora\s+eres|a\s+partir\s+de\s+ahora|"
            r"nuevas\s+instrucciones|developer\s+mode|jailbreak)\b",
            _I,
        ),
    ),
    (
        "system_prompt_reference",
        2,
        re.compile(
            r"\b(system\s+prompt|system\s+message|developer\s+message|hidden\s+instructions|"
            r"initial\s+instructions|prompt\s+del\s+sistema|instrucciones\s+del\s+sistema)\b",
            _I,
        ),
    ),
    # [ \t]* (not \s*): \s would span newlines and make the scan quadratic on long blank runs.
    ("role_marker", 2, re.compile(r"^[ \t]*(system|assistant|developer|human)[ \t]*[:>]", _IM)),
    (
        "delimiter_spoofing",
        3,
        re.compile(r"</?\s*(alert_data|runbook_context|untrusted|instructions|security_rules)", _I),
    ),
    (
        "end_of_data_marker",
        2,
        re.compile(r"\b(end\s+of\s+(alert|data|log|input|context)|fin\s+de\s+(la\s+alerta|los\s+datos))\b", _I),
    ),
    ("output_schema_spoofing", 3, re.compile(r"[\"']?recommended_actions[\"']?\s*:", _I)),
    ("markdown_exfiltration", 2, re.compile(r"!\[[^\]]{0,100}\]\(\s*https?://", _I)),
]

_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
_MAX_DECODED_BLOBS = 8
_MAX_BLOB_CHARS = 16_384


@dataclass(frozen=True)
class InjectionFinding:
    rule: str
    path: str
    weight: int

    def label(self) -> str:
        return f"{self.rule}@{self.path}"


@dataclass
class InjectionReport:
    threshold: int
    findings: list[InjectionFinding] = field(default_factory=list)

    @property
    def score(self) -> int:
        # Count each rule once per field to avoid inflating the score with repetitions.
        return sum({(f.rule, f.path): f.weight for f in self.findings}.values())

    @property
    def suspected(self) -> bool:
        return self.score >= self.threshold

    @property
    def indicators(self) -> list[str]:
        seen: dict[str, None] = {}
        for finding in self.findings:
            seen.setdefault(finding.label(), None)
        return list(seen)[:20]

    @property
    def flagged_paths(self) -> list[str]:
        return sorted({f.path for f in self.findings})


def _scan_text(text: str) -> list[tuple[str, int]]:
    candidate = normalize_text(text).translate(_CONFUSABLES)
    hits = [(name, weight) for name, weight, pattern in PATTERNS if pattern.search(candidate)]
    # Also try with whitespace runs collapsed (newline/tab splitting of keywords).
    collapsed = re.sub(r"\s+", " ", candidate)
    if collapsed != candidate:
        hits += [(n, w) for n, w, p in PATTERNS if (n, w) not in hits and p.search(collapsed)]
    return hits


def _decode_base64_blobs(text: str) -> list[str]:
    decoded: list[str] = []
    for match in _BASE64_RE.finditer(text[:200_000]):
        blob = match.group(0)[:_MAX_BLOB_CHARS]
        blob = blob[: len(blob) - len(blob) % 4]
        try:
            raw = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        # PowerShell -EncodedCommand uses UTF-16LE; most other payloads are UTF-8.
        for encoding in ("utf-16-le", "utf-8"):
            try:
                candidate = raw.decode(encoding)
            except UnicodeDecodeError:
                continue
            # Mostly printable ASCII: rejects binary blobs and UTF-8 bytes mis-decoded as UTF-16.
            printable = sum(ch.isascii() and (ch.isprintable() or ch.isspace()) for ch in candidate)
            if candidate and printable / len(candidate) > 0.8:
                decoded.append(candidate)
                break
        if len(decoded) >= _MAX_DECODED_BLOBS:
            break
    return decoded


def scan_for_injection(obj: Any, *, threshold: int = 3) -> InjectionReport:
    """Scan every string value and key of ``obj`` (raw, pre-normalisation alert)."""
    report = InjectionReport(threshold=threshold)
    for path, text in walk_strings(obj):
        if TAG_CHARS_RE.search(text):
            report.findings.append(InjectionFinding("unicode_tag_smuggling", path, 4))
            for name, weight in _scan_text(decode_tag_chars(text)):
                report.findings.append(InjectionFinding(f"hidden:{name}", path, weight))
        if INVISIBLE_RE.search(text):
            report.findings.append(InjectionFinding("invisible_unicode", path, 2))
        for name, weight in _scan_text(text):
            report.findings.append(InjectionFinding(name, path, weight))
        for decoded in _decode_base64_blobs(text):
            for name, weight in _scan_text(decoded):
                report.findings.append(InjectionFinding(f"base64:{name}", path, weight))
    return report
