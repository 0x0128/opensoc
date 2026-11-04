"""PII and secret redaction applied *before* any data leaves the service (OWASP LLM02).

Values are replaced with stable, per-request placeholders (``[IP_EXTERNAL_1]``, ``[USER_2]``...)
so the LLM can still correlate entities without ever seeing them. The mapping lives only in
memory for the duration of the request and can be used to re-hydrate the LLM answer locally.
Secrets and financial/national identifiers are never re-hydrated.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from collections.abc import Iterable
from enum import StrEnum
from typing import Any


class Category(StrEnum):
    SECRET = "SECRET"  # noqa: S105 - category label, not a credential
    EMAIL = "EMAIL"
    CARD = "CARD"
    IBAN = "IBAN"
    NATIONAL_ID = "NATIONAL_ID"
    SSN = "SSN"
    PHONE = "PHONE"
    MAC = "MAC"
    IP_INTERNAL = "IP_INTERNAL"
    IP_EXTERNAL = "IP_EXTERNAL"
    USER = "USER"


NON_REVERSIBLE = {Category.SECRET, Category.CARD, Category.IBAN, Category.NATIONAL_ID, Category.SSN}
SECRET_PLACEHOLDER = "[REDACTED_SECRET]"  # noqa: S105 - replacement marker

USER_KEYS = {
    "user", "username", "srcuser", "dstuser", "account", "accountname", "targetusername",
    "subjectusername", "targetuser", "logonuser", "login", "loginname", "owner", "uname",
    "unameafter", "unamebefore", "samaccountname", "userprincipalname", "principal",
    "fullname", "displayname", "givenname", "surname", "firstname", "lastname", "srcusername",
    "dstusername", "effectiveuser", "realuser", "loginuser",
}  # fmt: skip
SECRET_KEYS = {
    "password", "passwd", "pwd", "pass", "secret", "token", "apikey", "accesskey", "secretkey",
    "clientsecret", "authorization", "cookie", "setcookie", "sessionid", "privatekey",
    "credentials", "credential", "accesstoken", "refreshtoken",
}  # fmt: skip


def _norm_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _child_hint(key: object, parent_hint: str | None, user_keys: set[str]) -> str:
    """Key hint for a child value; ``{"user": {"name": "x"}}`` (Wazuh whodata) counts as a user."""
    hint = _norm_key(str(key))
    if hint == "name" and parent_hint in user_keys:
        return "user"
    return hint


# --- secret patterns (replaced by a fixed, non-reversible marker) --------------------------
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
        SECRET_PLACEHOLDER,
    ),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"), SECRET_PLACEHOLDER),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9\-._~+/]{8,}=*"), r"\1 " + SECRET_PLACEHOLDER),
    (
        re.compile(
            r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bxox[abposr]-[A-Za-z0-9-]{10,}"
            r"|\bsk-[A-Za-z0-9_-]{20,}"
        ),
        SECRET_PLACEHOLDER,
    ),
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,15}://)[^\s:/@]+:[^\s@/]+@"), r"\1" + SECRET_PLACEHOLDER + "@"),
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|pass|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|"
            r"auth[_-]?token|session[_-]?id|private[_-]?key|access[_-]?token)\b(\s*[:=]\s*)"
            r"(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
        ),
        r"\1\2" + SECRET_PLACEHOLDER,
    ),
]

_USER_KV_RE = re.compile(r"(?i)\b(user(?:name)?|login|account)(\s*[:=]\s*)([^\s&;,\"'\]\[]{2,64})")
_EMAIL_RE = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b")
_CARD_RE = re.compile(r"(?<![\d.])[2-6]\d{3}(?:[ -]?\d){9,15}(?![\d.])")
_DNI_RE = re.compile(r"\b\d{8}[A-Za-z]\b")
_NIE_RE = re.compile(r"\b[XYZxyz]\d{7}[A-Za-z]\b")
_SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_PHONE_RE = re.compile(r"(?<![\w+])\+\d{1,3}[\s.-]?(?:\(\d{1,4}\)[\s.-]?)?\d{2,4}(?:[\s.-]?\d{2,4}){1,4}(?!\w)")
_MAC_RE = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])")
_IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:.\w])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9A-Fa-f]{1,4}|\d{1,3}(?:\.\d{1,3}){3})?(?![0-9A-Fa-f:\w])"
)
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4_RE = re.compile(rf"(?<![\d.])(?:{_OCTET}\.){{3}}{_OCTET}(?![\d.])")

# What a SOC analyst calls "internal": RFC 1918, CGNAT, link-local and IPv6 ULA/link-local.
_INTERNAL_NETS = [
    ipaddress.ip_network(net)
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
                "fc00::/7", "fe80::/10")
]  # fmt: skip
_DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"
_REHYDRATE_RE = re.compile(r"\[(?:IP_INTERNAL|IP_EXTERNAL|EMAIL|USER|MAC|PHONE)_\d+\]")


def luhn_valid(number: str) -> bool:
    digits = [int(ch) for ch in number if ch.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def iban_valid(candidate: str) -> bool:
    compact = candidate.replace(" ", "")
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    try:
        number = int("".join(str(int(ch, 36)) for ch in rearranged))
    except ValueError:
        return False
    return number % 97 == 1


def spanish_id_valid(candidate: str) -> bool:
    value = candidate.upper()
    if value[0] in "XYZ":
        value = str("XYZ".index(value[0])) + value[1:]
    return _DNI_LETTERS[int(value[:8]) % 23] == value[8]


class PIIRedactor:
    """Per-request redactor. Not thread-safe; create one instance per alert."""

    def __init__(
        self,
        *,
        redact_ips: bool = True,
        extra_user_keys: Iterable[str] = (),
        keep_usernames: Iterable[str] = (),
    ) -> None:
        self._redact_ips = redact_ips
        self._user_keys = USER_KEYS | {_norm_key(key) for key in extra_user_keys}
        self._keep_users = {name.strip().lower() for name in keep_usernames if name.strip()}
        self._forward: dict[tuple[Category, str], str] = {}
        self._reverse: dict[str, str] = {}
        self._per_category: Counter[Category] = Counter()
        self._known_users: dict[str, str] = {}
        self._known_users_re: re.Pattern[str] | None = None
        self.counts: Counter[str] = Counter()

    # ------------------------------------------------------------------ placeholders
    def _placeholder(self, category: Category, original: str) -> str:
        if category is Category.USER and original.lower() in self._known_users:
            return self._known_users[original.lower()]
        key = (category, original if category is not Category.USER else original.lower())
        if key in self._forward:
            return self._forward[key]
        self._per_category[category] += 1
        self.counts[category.value] += 1
        placeholder = f"[{category.value}_{self._per_category[category]}]"
        self._forward[key] = placeholder
        if category not in NON_REVERSIBLE:
            self._reverse[placeholder] = original
        return placeholder

    def _secret(self) -> str:
        self.counts[Category.SECRET.value] += 1
        return SECRET_PLACEHOLDER

    # ------------------------------------------------------------------ public API
    def redact(self, obj: Any) -> Any:
        """Redact a nested alert structure (keys are preserved, values are redacted)."""
        self._collect_users(obj)
        return self._redact_obj(obj, None)

    def redact_text(self, text: str) -> str:
        for pattern, replacement in _SECRET_PATTERNS:
            text, n = pattern.subn(replacement, text)
            if n:
                self.counts[Category.SECRET.value] += n
        text = _EMAIL_RE.sub(lambda m: self._placeholder(Category.EMAIL, m.group(0)), text)
        text = _USER_KV_RE.sub(self._sub_user_kv, text)
        text = _IBAN_RE.sub(self._sub_validated(Category.IBAN, iban_valid), text)
        text = _CARD_RE.sub(self._sub_validated(Category.CARD, luhn_valid), text)
        text = _NIE_RE.sub(self._sub_validated(Category.NATIONAL_ID, spanish_id_valid), text)
        text = _DNI_RE.sub(self._sub_validated(Category.NATIONAL_ID, spanish_id_valid), text)
        text = _SSN_RE.sub(lambda m: self._placeholder(Category.SSN, m.group(0)), text)
        text = _PHONE_RE.sub(lambda m: self._placeholder(Category.PHONE, m.group(0)), text)
        text = _MAC_RE.sub(lambda m: self._placeholder(Category.MAC, m.group(0)), text)
        if self._redact_ips:
            text = _IPV6_RE.sub(self._sub_ip, text)
            text = _IPV4_RE.sub(self._sub_ip, text)
        if self._known_users_re is not None:
            text = self._known_users_re.sub(lambda m: self._known_users.get(m.group(0).lower(), m.group(0)), text)
        return text

    def rehydrate(self, text: str) -> str:
        """Restore reversible placeholders produced by this redactor (local use only)."""
        return _REHYDRATE_RE.sub(lambda m: self._reverse.get(m.group(0), m.group(0)), text)

    @property
    def placeholder_count(self) -> int:
        return len(self._forward)

    # ------------------------------------------------------------------ internals
    def _sub_validated(self, category: Category, validator: Any) -> Any:
        def _replace(match: re.Match[str]) -> str:
            value = match.group(0)
            return self._placeholder(category, value) if validator(value) else value

        return _replace

    def _sub_user_kv(self, match: re.Match[str]) -> str:
        key, sep, value = match.groups()
        if self._is_kept_user(value):
            return match.group(0)
        return f"{key}{sep}{self._placeholder(Category.USER, value)}"

    def _sub_ip(self, match: re.Match[str]) -> str:
        value = match.group(0)
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return value
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            return value
        internal = any(ip in net for net in _INTERNAL_NETS if net.version == ip.version)
        return self._placeholder(Category.IP_INTERNAL if internal else Category.IP_EXTERNAL, value)

    def _is_kept_user(self, value: str) -> bool:
        short = re.split(r"[\\/]", value)[-1].strip().lower()
        return short in self._keep_users or value.strip().lower() in self._keep_users

    def _collect_users(self, obj: Any, key_hint: str | None = None) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                self._collect_users(value, _child_hint(key, key_hint, self._user_keys))
        elif isinstance(obj, list):
            for value in obj:
                self._collect_users(value, key_hint)
        elif isinstance(obj, str) and key_hint in self._user_keys:
            value = obj.strip()
            if len(value) < 2 or self._is_kept_user(value) or value.startswith("["):
                return
            placeholder = self._placeholder(Category.USER, value)
            for alias in {value, re.split(r"[\\/]", value)[-1], value.split("@")[0]}:
                if len(alias) >= 3 and not self._is_kept_user(alias):
                    self._known_users[alias.lower()] = placeholder
        if key_hint is None and self._known_users:
            alternatives = "|".join(re.escape(u) for u in sorted(self._known_users, key=len, reverse=True))
            self._known_users_re = re.compile(rf"(?<![\w.@-])(?:{alternatives})(?![\w@-])", re.IGNORECASE)

    def _redact_obj(self, obj: Any, key_hint: str | None) -> Any:
        if isinstance(obj, dict):
            return {
                key: self._redact_obj(value, _child_hint(key, key_hint, self._user_keys)) for key, value in obj.items()
            }
        if isinstance(obj, list):
            return [self._redact_obj(value, key_hint) for value in obj]
        if key_hint in SECRET_KEYS and obj not in (None, "", True, False):
            return self._secret()
        if isinstance(obj, str):
            if key_hint in self._user_keys:
                value = obj.strip()
                if self._is_kept_user(value) or len(value) < 2:
                    return obj
                return self._placeholder(Category.USER, value)
            return self.redact_text(obj)
        return obj
