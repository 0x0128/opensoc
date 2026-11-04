"""Common IOC model, normalization, validation and (de)fanging."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

IOC_TYPES = ("ipv4", "ipv6", "domain", "hostname", "url", "email", "md5", "sha1", "sha256", "filename")
TLP_LEVELS = ("clear", "green", "amber", "amber+strict", "red")
_TLP_ALIASES = {"white": "clear"}

_HASH_LEN = {"md5": 32, "sha1": 40, "sha256": 64}
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_LABEL = r"(?!-)[a-z0-9_-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^(?=.{{1,253}}$)(?:{_LABEL}\.)+(?:[a-z]{{2,63}}|xn--[a-z0-9-]{{1,59}})$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Extensions that, without a "type" column, make "invoice.exe" be treated as a file name and not as a domain.
_FILE_EXTENSIONS = {
    "exe", "dll", "sys", "scr", "com", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf",
    "hta", "lnk", "msi", "iso", "img", "vhd", "jar", "doc", "docm", "docx", "xls", "xlsm", "xlsx",
    "ppt", "pptm", "pdf", "rtf", "one", "zip", "rar", "7z", "gz", "tar", "elf", "so", "bin", "sh", "py",
}


class IOCError(ValueError):
    """Invalid IOC value."""


# --------------------------------------------------------------------- fanging
_REFANG_PATTERNS = [
    (re.compile(r"\bhxxp(s?)", re.I), r"http\1"),
    (re.compile(r"\bfxp\b", re.I), "ftp"),
    (re.compile(r"\[(?:\.|dot)\]|\((?:\.|dot)\)|\{(?:\.|dot)\}", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[(?:@|at)\]|\((?:@|at)\)", re.I), "@"),
    (re.compile(r"\[/\]"), "/"),
]


def refang(value: str) -> str:
    """hxxps://evil[.]com -> https://evil.com"""
    for pattern, repl in _REFANG_PATTERNS:
        value = pattern.sub(repl, value)
    return value


def defang(ioc_type: str, value: str) -> str:
    """Safe version to paste into reports/tickets (not clickable)."""
    if ioc_type == "url":
        parts = urlsplit(value)
        scheme = parts.scheme.replace("http", "hxxp").replace("ftp", "fxp")
        host = parts.netloc.replace(".", "[.]")
        return urlunsplit((scheme, host, parts.path, parts.query, parts.fragment))
    if ioc_type in {"domain", "hostname", "ipv4"}:
        return value.replace(".", "[.]")
    if ioc_type == "ipv6":
        return value.replace(":", "[:]")
    if ioc_type == "email":
        local, _, domain = value.partition("@")
        return f"{local}[@]{domain.replace('.', '[.]')}"
    return value


# --------------------------------------------------------------- normalization
def normalize_tlp(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    if text.startswith("tlp:"):
        text = text[4:]
    text = _TLP_ALIASES.get(text, text)
    if text not in TLP_LEVELS:
        raise IOCError(f"invalid TLP: {value!r} (use {', '.join(TLP_LEVELS)})")
    return text


def normalize_timestamp(value: str | int | float | datetime | None) -> str | None:
    """Accepts ISO 8601, epoch (s) or datetime and returns 'YYYY-MM-DDTHH:MM:SSZ' in UTC."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, (int, float)) or (isinstance(value, str) and value.strip().isdigit()):
        moment = datetime.fromtimestamp(int(value), tz=timezone.utc)
    else:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            moment = datetime.fromisoformat(text)
        except ValueError as exc:
            raise IOCError(f"invalid date: {value!r}") from exc
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_ip(value: str) -> tuple[str, str]:
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            ioc_type = "ipv4" if net.version == 4 else "ipv6"
            if net.num_addresses == 1:
                return ioc_type, str(net.network_address)
            return ioc_type, str(net)
        addr = ipaddress.ip_address(value)
        return ("ipv4" if addr.version == 4 else "ipv6"), str(addr)
    except ValueError as exc:
        raise IOCError(f"invalid IP: {value!r}") from exc


def _normalize_url(value: str) -> str:
    parts = urlsplit(value)
    if not parts.scheme or not parts.netloc:
        raise IOCError(f"invalid URL (missing scheme or host): {value!r}")
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, parts.fragment))


def normalize_value(ioc_type: str, value: str) -> tuple[str, str]:
    """Returns the normalized (type, value) or raises IOCError."""
    if ioc_type not in IOC_TYPES:
        raise IOCError(f"unsupported IOC type: {ioc_type!r} (use {', '.join(IOC_TYPES)})")
    text = refang(str(value or "").strip())
    if not text:
        raise IOCError("empty value")
    if any(c in text for c in "\r\n\x00"):
        raise IOCError("the value contains line breaks or null characters")

    if ioc_type in {"ipv4", "ipv6"}:
        return _normalize_ip(text)
    if ioc_type in {"domain", "hostname"}:
        text = text.lower().rstrip(".")
        try:
            text = text.encode("idna").decode("ascii") if not text.isascii() else text
        except UnicodeError as exc:
            raise IOCError(f"invalid domain: {value!r}") from exc
        if not _DOMAIN_RE.match(text):
            raise IOCError(f"invalid domain: {value!r}")
        return ioc_type, text
    if ioc_type == "url":
        return ioc_type, _normalize_url(text)
    if ioc_type == "email":
        text = text.lower()
        if not _EMAIL_RE.match(text):
            raise IOCError(f"invalid email: {value!r}")
        return ioc_type, text
    if ioc_type in _HASH_LEN:
        text = text.lower()
        if len(text) != _HASH_LEN[ioc_type] or not _HEX_RE.match(text):
            raise IOCError(f"invalid {ioc_type.upper()}: {value!r}")
        return ioc_type, text
    # filename
    if "/" in text or "\\" in text:
        text = re.split(r"[\\/]", text)[-1]
        if not text:
            raise IOCError(f"invalid file name: {value!r}")
    return ioc_type, text


def detect_type(value: str) -> str:
    """Infers the type from the value (used when the CSV has no 'type' column)."""
    text = refang(str(value or "").strip())
    if not text:
        raise IOCError("empty value")
    try:
        return _normalize_ip(text)[0]
    except IOCError:
        pass
    lowered = text.lower()
    for name, length in _HASH_LEN.items():
        if len(lowered) == length and _HEX_RE.match(lowered):
            return name
    if re.match(r"^[a-z][a-z0-9+.-]*://", lowered):
        return "url"
    if _EMAIL_RE.match(lowered):
        return "email"
    if _DOMAIN_RE.match(lowered.rstrip(".")):
        if lowered.rsplit(".", 1)[-1] in _FILE_EXTENSIONS:
            return "filename"
        return "domain"
    if re.match(r"^[^\\/:*?\"<>|]+\.[a-z0-9]{1,8}$", lowered):
        return "filename"
    raise IOCError(f"cannot infer the type of {value!r}; fill in the 'type' column")


# ----------------------------------------------------------------------- model
@dataclass
class IOC:
    type: str
    value: str
    description: str = ""
    tags: list[str] = field(default_factory=list)
    tlp: str | None = None
    confidence: int | None = None
    first_seen: str | None = None
    source: str = ""
    to_ids: bool = True

    def __post_init__(self):
        self.type, self.value = normalize_value(str(self.type).strip().lower(), self.value)
        self.description = " ".join(str(self.description or "").split())
        self.tags = list(dict.fromkeys(t.strip() for t in self.tags if t and t.strip()))
        # A tlp:* tag becomes the tlp field so that the information is not duplicated.
        for tag in list(self.tags):
            if tag.lower().startswith("tlp:"):
                self.tags.remove(tag)
                if self.tlp is None:
                    try:
                        self.tlp = normalize_tlp(tag)
                    except IOCError:
                        pass
        self.tlp = normalize_tlp(self.tlp)
        if self.confidence is not None and self.confidence != "":
            try:
                self.confidence = int(self.confidence)
            except (TypeError, ValueError) as exc:
                raise IOCError(f"confidence must be an integer 0-100: {self.confidence!r}") from exc
            if not 0 <= self.confidence <= 100:
                raise IOCError(f"confidence out of range (0-100): {self.confidence}")
        else:
            self.confidence = None
        self.first_seen = normalize_timestamp(self.first_seen)
        self.source = str(self.source or "").strip()
        self.to_ids = bool(self.to_ids)

    @property
    def key(self) -> tuple[str, str]:
        return self.type, self.value

    def with_changes(self, **changes) -> IOC:
        return replace(self, **changes)


def dedupe(iocs: Iterable[IOC]) -> list[IOC]:
    """Removes (type, value) duplicates keeping the first one and merging tags."""
    result: dict[tuple[str, str], IOC] = {}
    for ioc in iocs:
        if ioc.key in result:
            kept = result[ioc.key]
            kept.tags = list(dict.fromkeys(kept.tags + ioc.tags))
            if not kept.description and ioc.description:
                kept.description = ioc.description
        else:
            result[ioc.key] = replace(ioc, tags=list(ioc.tags))
    return list(result.values())
