"""Turn a normalized test event (Sigma field names) into the raw input Wazuh receives.

Sample events in ``tests/samples`` are written with the Sigma field names of the
rule's logsource. To run them through ``wazuh-logtest`` they are rendered into the
format the Wazuh manager actually ingests for that source:

* ``json``   - JSON documents (EventChannel after decoding, Suricata EVE, cloud
               modules). Sigma fields are renamed with the same mapping the
               converter uses and merged into the source envelope.
* ``audit``  - a Linux audit event exactly as the Wazuh agent forwards it
               (SYSCALL, EXECVE, CWD, PATH, PROCTITLE records on one line).
               Arguments containing spaces/quotes are hex-encoded like auditd does.
* ``syslog`` - a classic syslog line ``<date> <host> <program>[<pid>]: <message>``.
"""

from __future__ import annotations

import copy
import json
from typing import Any

from opensoc_detections.config import LogsourceMapping

AUDIT_TS = "1730714400.123:4242"


def _set_path(doc: dict, dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = doc
    for p in parts[:-1]:
        nxt = cur.get(p)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[p] = nxt
        cur = nxt
    cur[parts[-1]] = value


def _deep_merge(base: dict, extra: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in extra.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _stringify(value: Any) -> Any:
    """Windows EventChannel delivers every event data value as a string."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return value


def render_json(event: dict, mapping: LogsourceMapping) -> str:
    mapped: dict = {}
    for key, value in event.items():
        target = mapping.fields.target(key)
        if target is None:
            raise KeyError(f"sample field '{key}' is not mapped for logsource '{mapping.id}'")
        if target.startswith("win."):
            value = _stringify(value)
        _set_path(mapped, target, value)
    doc = _deep_merge(mapping.render.get("envelope", {}), mapped)
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"))


def _audit_value(value: Any) -> str:
    s = str(value)
    if any(c in s for c in ' "\'\\') or any(ord(c) < 0x21 or ord(c) > 0x7E for c in s):
        return s.encode("utf-8").hex().upper()
    return f'"{s}"'


def render_audit(event: dict, mapping: LogsourceMapping) -> str:
    unknown = set(event) - set(mapping.fields.map) - set(mapping.fields.drop) - {"pid", "ppid"}
    if unknown:
        raise KeyError(f"sample fields {sorted(unknown)} are not supported by the audit renderer")
    args = []
    i = 0
    while f"a{i}" in event:
        args.append(str(event[f"a{i}"]))
        i += 1
    comm = event.get("comm") or (args[0].rsplit("/", 1)[-1] if args else "bash")
    exe = event.get("exe") or f"/usr/bin/{comm}"
    key = event.get("key")
    key_s = f'"{key}"' if key else "(null)"
    msg = f"msg=audit({AUDIT_TS}):"
    records = [
        f"type=SYSCALL {msg} arch=c000003e syscall={event.get('syscall', 59)} "
        f"success={event.get('success', 'yes')} exit=0 a0=55d4c3a1b2c0 a1=55d4c3a1b2e0 "
        f"a2=55d4c3a1b300 a3=0 items={2 if 'name' in event else 1} ppid={event.get('ppid', 2120)} "
        f"pid={event.get('pid', 2121)} auid={event.get('auid', 1000)} uid={event.get('uid', 0)} gid=0 "
        f"euid={event.get('euid', 0)} suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty={event.get('tty', 'pts0')} "
        f'ses=3 comm="{comm}" exe="{exe}" subj=unconfined key={key_s}'
    ]
    if args:
        records.append(
            f"type=EXECVE {msg} argc={len(args)} " + " ".join(f"a{n}={_audit_value(a)}" for n, a in enumerate(args))
        )
    records.append(f'type=CWD {msg} cwd="{event.get("cwd", "/root")}"')
    if "name" in event:
        records.append(
            f'type=PATH {msg} item=0 name="{event["name"]}" inode=131090 dev=fd:00 mode=0100644 '
            "ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0"
        )
    records.append(f"type=PROCTITLE {msg} proctitle={' '.join(args or [comm]).encode().hex().upper()}")
    return " ".join(records)


def render_syslog(event: dict, mapping: LogsourceMapping) -> str:
    if "message" not in event:
        raise KeyError("syslog samples need a 'message' field")
    program = event.get("program", mapping.render.get("program", "app"))
    host = event.get("hostname", "srv01")
    pid = event.get("pid", 1337)
    return f"Nov  4 10:00:00 {host} {program}[{pid}]: {event['message']}"


RENDERERS = {"json": render_json, "audit": render_audit, "syslog": render_syslog}


def render(event: dict, mapping: LogsourceMapping) -> dict[str, str]:
    """Return the wazuh-logtest request parameters for a sample event."""
    fmt = mapping.render.get("format", "json")
    raw = RENDERERS[fmt](event, mapping)
    return {
        "event": raw,
        "log_format": {"json": "json", "audit": "audit", "syslog": "syslog"}[fmt],
        "location": mapping.render.get("location", "opensoc-test"),
    }
