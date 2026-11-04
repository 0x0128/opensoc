#!/usr/bin/env python3
# OpenSOC - Wazuh -> TheHive integration (wazuh-integratord "custom-thehive").
#
# Creates a TheHive 5 alert for every Wazuh alert routed to this integration and,
# when the rule level is >= options.case_level, promotes it to a case.
#
# Invoked by wazuh-integratord as:
#   custom-thehive <alert_file> <api_key> <hook_url> [debug] [<options_file>] <timeout> <retries>
# Empty arguments may be dropped by integratord, so arguments are recognised by shape.
#
# Options (JSON, from <options> in ossec.conf):
#   organisation  TheHive organisation (X-Organisation header), optional
#   case_level    promote to case when rule.level >= case_level (0 disables), default 12
#   tlp / pap     TLP and PAP of the created alerts, default 2 / 2
#   skip_groups   list of Wazuh rule groups that must not be sent (handled elsewhere)
#
# Only the Python standard library is used (runs on Wazuh's embedded interpreter).

import json
import os
import sys
import time
import urllib.error
import urllib.request

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs", "integrations.log")
ALERT_TYPE = "wazuh"
MAX_DESCRIPTION = 60000
DEBUG = False


def log(msg, debug_only=False):
    if debug_only and not DEBUG:
        return
    line = "%s custom-thehive: %s" % (time.strftime("%Y/%m/%d %H:%M:%S"), msg)
    try:
        with open(LOG_FILE, "a") as handle:
            handle.write(line + "\n")
    except OSError:
        pass
    if DEBUG:
        print(line)


def parse_args(argv):
    """Return (alert_file, api_key, hook_url, options_file)."""
    global DEBUG
    if len(argv) < 2:
        raise SystemExit("usage: custom-thehive <alert_file> <api_key> <hook_url> [debug] [options_file]")
    alert_file, api_key, hook_url, options_file = argv[1], "", "", ""
    for token in argv[2:]:
        if not token:
            continue
        if token == "debug":
            DEBUG = True
        elif token.startswith("http://") or token.startswith("https://"):
            hook_url = token
        elif token.endswith(".options") and os.path.isfile(token):
            options_file = token
        elif token.isdigit():
            continue  # timeout / retries
        elif not api_key:
            api_key = token
    return alert_file, api_key, hook_url.rstrip("/"), options_file


def load_json(path, default=None):
    if not path:
        return default
    with open(path) as handle:
        content = handle.read().strip()
    if not content:
        return default
    # Alert files contain exactly one JSON document (first line is enough).
    try:
        return json.loads(content)
    except ValueError:
        return json.loads(content.splitlines()[0])


def get(obj, path, default=None):
    for key in path.split("."):
        if not isinstance(obj, dict) or key not in obj:
            return default
        obj = obj[key]
    return obj


def severity_from_level(level):
    if level >= 13:
        return 4
    if level >= 10:
        return 3
    if level >= 7:
        return 2
    return 1


def build_observables(alert, mark_ioc):
    candidates = [
        ("ip", "data.srcip", "Source IP"),
        ("ip", "data.src_ip", "Source IP"),
        ("ip", "data.dstip", "Destination IP"),
        ("ip", "data.dest_ip", "Destination IP"),
        ("ip", "data.win.eventdata.ipAddress", "Source IP (Windows)"),
        ("domain", "data.http.hostname", "HTTP host"),
        ("domain", "data.dns.rrname", "DNS query"),
        ("domain", "data.tls.sni", "TLS SNI"),
        ("url", "data.url", "URL"),
        ("hash", "syscheck.md5_after", "File MD5"),
        ("hash", "syscheck.sha1_after", "File SHA1"),
        ("hash", "syscheck.sha256_after", "File SHA256"),
        ("filename", "syscheck.path", "File path"),
        ("hostname", "agent.name", "Wazuh agent"),
    ]
    observables, seen = [], set()
    for data_type, path, label in candidates:
        value = get(alert, path)
        if not value or not isinstance(value, (str, int)):
            continue
        value = str(value).strip()
        if not value or (data_type, value) in seen:
            continue
        seen.add((data_type, value))
        observable = {"dataType": data_type, "data": value, "message": label, "tags": ["wazuh"]}
        if mark_ioc and data_type in ("ip", "domain", "hash", "url"):
            observable["ioc"] = True
            observable["tags"].append("misp")
        observables.append(observable)
    return observables


def build_alert(alert, options):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    level = int(rule.get("level", 0))
    groups = rule.get("groups", []) or []
    mitre = rule.get("mitre", {}) or {}
    mitre_ids = mitre.get("id", []) or []

    tags = ["wazuh", "wazuh:rule=%s" % rule.get("id", "?"), "wazuh:level=%d" % level]
    if agent.get("name"):
        tags.append("wazuh:agent=%s" % agent["name"])
    tags += ["wazuh:group=%s" % g for g in groups]
    tags += ["mitre:%s" % t for t in mitre_ids]

    lines = [
        "**Wazuh rule** `%s` (level %d): %s" % (rule.get("id", "?"), level, rule.get("description", "")),
        "",
        "| Field | Value |",
        "|---|---|",
        "| Timestamp | %s |" % alert.get("timestamp", ""),
        "| Agent | %s (id %s, %s) |" % (agent.get("name", "-"), agent.get("id", "-"), agent.get("ip", "-")),
        "| Manager | %s |" % get(alert, "manager.name", "-"),
        "| Location | `%s` |" % alert.get("location", "-"),
        "| Groups | %s |" % ", ".join(groups),
    ]
    if mitre_ids:
        lines.append("| MITRE ATT&CK | %s (%s) |" % (", ".join(mitre_ids), ", ".join(mitre.get("tactic", []) or [])))
    if alert.get("full_log"):
        lines += ["", "**Full log**", "", "```", str(alert["full_log"])[:8000], "```"]
    lines += ["", "**Raw alert**", "", "```json", json.dumps(alert, indent=2, sort_keys=True)[:40000], "```"]
    description = "\n".join(lines)[:MAX_DESCRIPTION]

    created = None
    try:
        # Wazuh timestamp: 2026-11-04T21:00:00.123+0000
        created = int(time.mktime(time.strptime(alert["timestamp"][:19], "%Y-%m-%dT%H:%M:%S")) * 1000)
    except (KeyError, ValueError):
        pass

    payload = {
        "type": ALERT_TYPE,
        "source": get(alert, "manager.name", "wazuh-manager"),
        "sourceRef": str(alert.get("id", int(time.time() * 1000))),
        "title": ("[Wazuh] %s" % rule.get("description", "Wazuh alert"))[:500],
        "description": description,
        "severity": severity_from_level(level),
        "tlp": int(options.get("tlp", 2)),
        "pap": int(options.get("pap", 2)),
        "tags": tags,
        "observables": build_observables(alert, mark_ioc="misp_ioc" in groups or "malware" in groups),
    }
    if created:
        payload["date"] = created
    return payload


def request(method, url, api_key, organisation, body=None, timeout=15):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Bearer %s" % api_key)
    req.add_header("Content-Type", "application/json")
    if organisation:
        req.add_header("X-Organisation", organisation)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as err:
        text = err.read().decode(errors="replace")
        try:
            return err.code, json.loads(text)
        except ValueError:
            return err.code, {"message": text}


def main(argv):
    alert_file, api_key, hook_url, options_file = parse_args(argv)
    options = load_json(options_file, {}) or {}
    alert = load_json(alert_file)
    if not alert:
        log("empty alert file %s" % alert_file)
        return 0
    if not api_key or not hook_url:
        log("TheHive API key or URL not configured yet (run infra/install.sh); alert %s not sent" % alert.get("id"))
        return 0

    groups = set(get(alert, "rule.groups", []) or [])
    skip = groups.intersection(options.get("skip_groups", []) or [])
    if skip:
        log("alert %s skipped (groups %s are handled by another integration)" % (alert.get("id"), ",".join(sorted(skip))), True)
        return 0

    organisation = options.get("organisation", "")
    payload = build_alert(alert, options)
    status, body = None, {}
    for attempt in range(3):
        try:
            status, body = request("POST", hook_url + "/api/v1/alert", api_key, organisation, payload)
            break
        except (urllib.error.URLError, OSError) as err:
            log("attempt %d: cannot reach TheHive at %s: %s" % (attempt + 1, hook_url, err))
            time.sleep(2 * (attempt + 1))
    if status is None:
        return 1
    if status == 400 and "already exists" in json.dumps(body).lower():
        log("alert %s already exists in TheHive" % payload["sourceRef"], True)
        return 0
    if status not in (200, 201):
        log("TheHive rejected alert %s: HTTP %s %s" % (payload["sourceRef"], status, json.dumps(body)[:500]))
        return 1
    alert_id = body.get("_id")
    log("alert %s -> TheHive alert %s (rule %s)" % (payload["sourceRef"], alert_id, get(alert, "rule.id")))

    case_level = int(options.get("case_level", 12) or 0)
    level = int(get(alert, "rule.level", 0))
    if case_level and level >= case_level and alert_id:
        status, case = request("POST", "%s/api/v1/alert/%s/case" % (hook_url, alert_id), api_key, organisation, {})
        if status in (200, 201):
            log("alert %s promoted to case #%s" % (alert_id, case.get("number")))
        else:
            log("could not promote alert %s to case: HTTP %s %s" % (alert_id, status, json.dumps(case)[:500]))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as exc:  # never crash integratord with a traceback
        log("unexpected error: %r" % exc)
        sys.exit(1)
