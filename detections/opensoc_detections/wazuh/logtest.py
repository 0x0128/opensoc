"""Run events through a real ``wazuh-logtest`` (Wazuh manager in Docker).

The integration harness starts (or reuses) a container from the official
``wazuh/wazuh-manager`` image, installs the generated ruleset plus the test-only
EventChannel decoder shim, and feeds rendered sample events through the logtest
Unix socket. Results carry the rule that finally matched, the decoder and any
ruleset warnings Wazuh emitted while loading the session.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from opensoc_detections.config import LOGTEST_DIR, WAZUH_OUTPUT

IMAGE = os.environ.get("OPENSOC_WAZUH_IMAGE", "wazuh/wazuh-manager:4.9.2")
CONTAINER = os.environ.get("OPENSOC_WAZUH_CONTAINER", "opensoc-wazuh-logtest")
CLIENT = LOGTEST_DIR / "logtest_client.py"
SHIM = LOGTEST_DIR / "0000-opensoc-logtest-winevt_decoder.xml"
PYTHON = "/var/ossec/framework/python/bin/python3"
RULES_DEST = "/var/ossec/etc/rules/opensoc_sigma_rules.xml"
SHIM_DEST = "/var/ossec/etc/decoders/0000-opensoc-logtest-winevt_decoder.xml"
CLIENT_DEST = "/tmp/opensoc_logtest_client.py"


class LogtestUnavailable(RuntimeError):
    pass


def _docker(*args: str, check: bool = True, input: str | None = None, timeout: int = 600):
    return subprocess.run(
        ["docker", *args], check=check, capture_output=True, text=True, input=input, timeout=timeout
    )


def docker_available() -> tuple[bool, str]:
    if shutil.which("docker") is None:
        return False, "docker binary not found"
    res = _docker("info", "--format", "{{.ServerVersion}}", check=False, timeout=60)
    if res.returncode != 0:
        return False, f"docker daemon not reachable: {res.stderr.strip()[:200]}"
    return True, res.stdout.strip()


class WazuhLogtest:
    def __init__(self, container: str = CONTAINER, image: str = IMAGE):
        self.container = container
        self.image = image

    # -- lifecycle -----------------------------------------------------------
    def running(self) -> bool:
        res = _docker("inspect", "-f", "{{.State.Running}}", self.container, check=False)
        return res.returncode == 0 and res.stdout.strip() == "true"

    def start(self, timeout: int = 240) -> None:
        ok, reason = docker_available()
        if not ok:
            raise LogtestUnavailable(reason)
        if not self.running():
            _docker("rm", "-f", self.container, check=False)
            res = _docker("run", "-d", "--name", self.container, self.image, check=False, timeout=900)
            if res.returncode != 0:
                raise LogtestUnavailable(f"cannot start {self.image}: {res.stderr.strip()[:300]}")
        deadline = time.time() + timeout
        while time.time() < deadline:
            res = _docker("exec", self.container, "test", "-S", "/var/ossec/queue/sockets/logtest", check=False)
            if res.returncode == 0:
                return
            time.sleep(2)
        raise LogtestUnavailable("wazuh-logtest socket did not come up in time")

    def stop(self) -> None:
        _docker("rm", "-f", self.container, check=False)

    def install(self, rules_xml: Path = WAZUH_OUTPUT) -> None:
        for src, dest in ((rules_xml, RULES_DEST), (SHIM, SHIM_DEST), (CLIENT, CLIENT_DEST)):
            _docker("cp", str(src), f"{self.container}:{dest}")
        _docker("exec", self.container, "chown", "wazuh:wazuh", RULES_DEST, SHIM_DEST)
        _docker("exec", self.container, "chmod", "660", RULES_DEST, SHIM_DEST)

    # -- processing ------------------------------------------------------------
    def process(self, requests: list[dict]) -> list[dict]:
        payload = "\n".join(json.dumps(r, ensure_ascii=False) for r in requests) + "\n"
        res = _docker("exec", "-i", self.container, PYTHON, CLIENT_DEST, input=payload, check=False)
        if res.returncode != 0:
            raise RuntimeError(f"logtest client failed: {res.stderr.strip()[:2000]}")
        results = [json.loads(line) for line in res.stdout.splitlines() if line.strip()]
        if len(results) != len(requests):
            raise RuntimeError(f"expected {len(requests)} logtest results, got {len(results)}")
        return results

    def ruleset_warnings(self) -> list[str]:
        """Warnings/errors Wazuh prints while loading the ruleset for a new session."""
        probe = {"event": "opensoc ruleset probe", "log_format": "syslog", "location": "opensoc"}
        result = self.process([probe])[0]
        return [m for m in result["messages"] if not m.startswith("INFO")]
