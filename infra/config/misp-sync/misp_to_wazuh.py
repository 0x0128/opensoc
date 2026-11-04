#!/usr/bin/env python3
"""OpenSOC - MISP -> Wazuh IOC synchronisation.

Periodically exports MISP attributes flagged for detection (to_ids) into the Wazuh
CDB lists used by the built-in malicious-ioc ruleset, then asks wazuh-analysisd to
reload its ruleset when the lists changed.

  malicious-ip       ip-src, ip-dst, ip-src|port, ip-dst|port, domain|ip
  malicious-domains  domain, hostname, domain|ip
  malware-hashes     md5, sha1, sha256, filename|md5, filename|sha1, filename|sha256

Usage:
  misp_to_wazuh.py               run forever (every SYNC_INTERVAL seconds)
  misp_to_wazuh.py --once        run a single synchronisation and exit (0 = success)
  misp_to_wazuh.py --healthcheck exit 0 if the last successful sync is recent

Environment: MISP_URL, MISP_API_KEY, MISP_VERIFY_TLS (default false), LISTS_DIR,
SYNC_INTERVAL (s, default 300), IOC_MAX_AGE (MISP relative time such as 90d; empty
for no limit), WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD,
WAZUH_VERIFY_TLS (default false: the Wazuh API uses a self-signed certificate).

Only the Python standard library is used.
"""

import base64
import hashlib
import ipaddress
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

MISP_URL = os.environ.get("MISP_URL", "http://misp").rstrip("/")
MISP_API_KEY = os.environ.get("MISP_API_KEY", "")
MISP_VERIFY_TLS = os.environ.get("MISP_VERIFY_TLS", "false").lower() == "true"
LISTS_DIR = os.environ.get("LISTS_DIR", "/lists")
SYNC_INTERVAL = int(os.environ.get("SYNC_INTERVAL", "300"))
IOC_MAX_AGE = os.environ.get("IOC_MAX_AGE", "90d").strip()
WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://wazuh.manager:55000").rstrip("/")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "")
WAZUH_VERIFY_TLS = os.environ.get("WAZUH_VERIFY_TLS", "false").lower() == "true"
STATE_FILE = os.environ.get("STATE_FILE", "/tmp/misp-ioc-sync.json")
PAGE_SIZE = 5000

LISTS = {
    "malicious-ip": ["ip-src", "ip-dst", "ip-src|port", "ip-dst|port", "domain|ip"],
    "malicious-domains": ["domain", "hostname", "domain|ip"],
    "malware-hashes": ["md5", "sha1", "sha256", "filename|md5", "filename|sha1", "filename|sha256"],
}


def log(msg):
    print("%s misp-ioc-sync: %s" % (time.strftime("%Y-%m-%dT%H:%M:%S"), msg), flush=True)


def ssl_context(verify):
    if verify:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def http(method, url, headers=None, body=None, verify=True, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    ctx = ssl_context(verify) if url.startswith("https") else None
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return json.loads(resp.read().decode() or "{}")


def misp_attributes(types):
    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    query = {
        "returnFormat": "json",
        "type": types,
        "to_ids": True,
        "deleted": False,
        "enforceWarninglist": True,
        "includeEventTags": False,
        "limit": PAGE_SIZE,
    }
    if IOC_MAX_AGE:
        query["timestamp"] = IOC_MAX_AGE
    page = 1
    while True:
        query["page"] = page
        result = http("POST", MISP_URL + "/attributes/restSearch", headers, query, MISP_VERIFY_TLS, timeout=300)
        attributes = result.get("response", {}).get("Attribute", [])
        for attribute in attributes:
            yield attribute
        if len(attributes) < PAGE_SIZE:
            return
        page += 1


def normalise(list_name, attribute):
    """Return the CDB key for an attribute, or None if it cannot be used."""
    attr_type, value = attribute.get("type", ""), str(attribute.get("value", "")).strip()
    if "|" in attr_type:
        left, _, right = value.partition("|")
        if attr_type == "domain|ip":
            value = right if list_name == "malicious-ip" else left
        elif attr_type.endswith("|port"):
            value = left
        else:  # filename|hash
            value = right
    value = value.strip().lower() if list_name != "malicious-ip" else value.strip()
    if not value:
        return None
    if list_name == "malicious-ip":
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None
        if network.num_addresses != 1:  # CIDR ranges cannot be matched with match_key
            return None
        value = str(network.network_address)
    if list_name == "malicious-domains":
        value = value.rstrip(".")
    if list_name == "malware-hashes" and not all(c in "0123456789abcdef" for c in value):
        return None
    return value


def cdb_line(key, value):
    # Keys containing ':' (IPv6) must be quoted in Wazuh CDB lists.
    if ":" in key or '"' in key:
        key = '"%s"' % key.replace('"', "")
    return "%s:%s" % (key, value)


def write_list(name, entries):
    path = os.path.join(LISTS_DIR, name)
    lines = [cdb_line(key, value) for key, value in sorted(entries.items())]
    content = ("\n".join(lines) + "\n") if lines else ""
    try:
        with open(path) as handle:
            if handle.read() == content:
                return False
    except FileNotFoundError:
        pass
    tmp = path + ".tmp"
    with open(tmp, "w") as handle:
        handle.write(content)
    os.chmod(tmp, 0o664)
    os.replace(tmp, path)
    return True


def ensure_lists_exist():
    os.makedirs(LISTS_DIR, exist_ok=True)
    for name in LISTS:
        path = os.path.join(LISTS_DIR, name)
        if not os.path.exists(path):
            open(path, "a").close()
            os.chmod(path, 0o664)


def reload_analysisd():
    token_url = WAZUH_API_URL + "/security/user/authenticate?raw=true"
    credentials = base64.b64encode(("%s:%s" % (WAZUH_API_USER, WAZUH_API_PASSWORD)).encode()).decode()
    req = urllib.request.Request(token_url, method="POST", headers={"Authorization": "Basic " + credentials})
    with urllib.request.urlopen(req, timeout=30, context=ssl_context(WAZUH_VERIFY_TLS)) as resp:
        token = resp.read().decode().strip()
    result = http("PUT", WAZUH_API_URL + "/manager/analysisd/reload",
                  {"Authorization": "Bearer " + token}, None, WAZUH_VERIFY_TLS)
    if result.get("error", 0) != 0:
        raise RuntimeError("analysisd reload failed: %s" % json.dumps(result)[:300])


def save_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as handle:
        json.dump(state, handle)
    os.replace(tmp, STATE_FILE)


def load_state():
    try:
        with open(STATE_FILE) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def sync_once():
    if not MISP_API_KEY:
        raise RuntimeError("MISP_API_KEY is not set")
    ensure_lists_exist()
    counts, changed = {}, False
    for name, types in LISTS.items():
        entries = {}
        for attribute in misp_attributes(types):
            key = normalise(name, attribute)
            if key:
                entries.setdefault(key, "misp-event-%s" % attribute.get("event_id", "0"))
        counts[name] = len(entries)
        changed |= write_list(name, entries)
    state = load_state()
    if changed or state.get("pending_reload"):
        try:
            reload_analysisd()
            state["pending_reload"] = False
            log("IOC lists changed, analysisd ruleset reloaded")
        except (urllib.error.URLError, OSError, RuntimeError) as err:
            state["pending_reload"] = True
            log("WARNING: lists updated but analysisd reload failed (will retry): %s" % err)
    state.update({"last_success": int(time.time()), "counts": counts,
                  "digest": hashlib.sha256(json.dumps(counts, sort_keys=True).encode()).hexdigest()})
    save_state(state)
    log("sync OK %s" % json.dumps(counts, sort_keys=True))
    return state


def healthcheck():
    state = load_state()
    last = state.get("last_success")
    if not last:
        print("no successful sync yet")
        return 1
    age = time.time() - last
    if age > max(3 * SYNC_INTERVAL, 900):
        print("last successful sync %ds ago" % age)
        return 1
    print("ok: last sync %ds ago %s" % (age, json.dumps(state.get("counts", {}))))
    return 0


def main(argv):
    if "--healthcheck" in argv:
        return healthcheck()
    if "--once" in argv:
        try:
            sync_once()
            return 0
        except Exception as err:  # report and fail
            log("ERROR: %s" % err)
            return 1
    log("starting: MISP %s -> %s every %ss (max IOC age: %s)" % (MISP_URL, LISTS_DIR, SYNC_INTERVAL, IOC_MAX_AGE or "none"))
    ensure_lists_exist()
    while True:
        try:
            sync_once()
            delay = SYNC_INTERVAL
        except Exception as err:  # MISP still starting, network error...
            log("sync failed, retrying in 30s: %s" % err)
            delay = 30
        time.sleep(delay)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
