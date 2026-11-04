#!/usr/bin/env python3
"""Unit tests for the OpenSOC integration scripts (no network, standard library only).

    python3 -m unittest discover -s infra/tests -v
"""

import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import unittest

CONFIG = pathlib.Path(__file__).resolve().parent.parent / "config"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


thehive = load("custom_thehive", CONFIG / "wazuh" / "integrations" / "custom-thehive.py")

SURICATA_IOC_ALERT = {
    "timestamp": "2026-11-04T21:39:27.123+0000",
    "id": "1730756367.123456",
    "rule": {
        "id": "100101", "level": 12,
        "description": "MISP IOC: Suricata alert to destination IP 198.51.100.77 listed in MISP",
        "groups": ["opensoc", "misp_ioc", "misp_ioc_network"],
        "mitre": {"id": ["T1071"], "tactic": ["Command and Control"]},
    },
    "agent": {"id": "000", "name": "wazuh.manager"},
    "manager": {"name": "wazuh.manager"},
    "location": "/var/log/suricata/eve.json",
    "data": {"src_ip": "192.0.2.2", "dest_ip": "198.51.100.77", "event_type": "alert",
             "alert": {"signature": "OPENSOC self-test - IDS pipeline probe", "severity": "1"}},
    "full_log": "{\"event_type\":\"alert\"}",
}


class CustomTheHiveTest(unittest.TestCase):
    def test_parse_args_with_all_arguments(self):
        with tempfile.NamedTemporaryFile(suffix=".options", delete=False) as opts:
            path = opts.name
        try:
            argv = ["custom-thehive", "/tmp/a.alert", "KEY123", "http://thehive:9000/", "debug", path, "10", "3"]
            self.assertEqual(thehive.parse_args(argv), ("/tmp/a.alert", "KEY123", "http://thehive:9000", path))
        finally:
            os.unlink(path)

    def test_parse_args_tolerates_dropped_empty_arguments(self):
        argv = ["custom-thehive", "/tmp/a.alert", "http://thehive:9000", "10", "3"]
        self.assertEqual(thehive.parse_args(argv), ("/tmp/a.alert", "", "http://thehive:9000", ""))

    def test_severity_mapping(self):
        self.assertEqual([thehive.severity_from_level(level) for level in (3, 7, 10, 12, 13, 15)], [1, 2, 3, 3, 4, 4])

    def test_build_alert(self):
        alert = thehive.build_alert(SURICATA_IOC_ALERT, {"tlp": 2, "pap": 2})
        self.assertEqual(alert["type"], "wazuh")
        self.assertEqual(alert["sourceRef"], SURICATA_IOC_ALERT["id"])
        self.assertEqual(alert["severity"], 3)
        self.assertTrue(alert["title"].startswith("[Wazuh] MISP IOC"))
        self.assertIn("mitre:T1071", alert["tags"])
        self.assertIn("wazuh:group=misp_ioc", alert["tags"])
        observables = {(o["dataType"], o["data"]): o for o in alert["observables"]}
        self.assertIn(("ip", "198.51.100.77"), observables)
        self.assertIn(("ip", "192.0.2.2"), observables)
        self.assertIn(("hostname", "wazuh.manager"), observables)
        self.assertTrue(observables[("ip", "198.51.100.77")]["ioc"])
        self.assertNotIn("ioc", observables[("hostname", "wazuh.manager")])
        json.dumps(alert)  # must be serialisable

    def test_skip_groups(self):
        with tempfile.TemporaryDirectory() as tmp:
            alert_file = pathlib.Path(tmp, "a.alert")
            alert_file.write_text(json.dumps(SURICATA_IOC_ALERT))
            options = pathlib.Path(tmp, "x.options")
            options.write_text(json.dumps({"skip_groups": ["misp_ioc_network"]}))
            # The URL is unreachable: the call must return before any request.
            argv = ["custom-thehive", str(alert_file), "KEY", "http://127.0.0.1:9", str(options)]
            self.assertEqual(thehive.main(argv), 0)


class MispSyncTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ["LISTS_DIR"] = cls.tmp.name
        os.environ["STATE_FILE"] = os.path.join(cls.tmp.name, "state.json")
        sys.modules.pop("misp_to_wazuh", None)
        cls.sync = load("misp_to_wazuh", CONFIG / "misp-sync" / "misp_to_wazuh.py")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def norm(self, list_name, attr_type, value):
        return self.sync.normalise(list_name, {"type": attr_type, "value": value})

    def test_ip_normalisation(self):
        self.assertEqual(self.norm("malicious-ip", "ip-dst", "198.51.100.77"), "198.51.100.77")
        self.assertEqual(self.norm("malicious-ip", "ip-src", "198.51.100.77/32"), "198.51.100.77")
        self.assertEqual(self.norm("malicious-ip", "ip-dst|port", "198.51.100.77|443"), "198.51.100.77")
        self.assertEqual(self.norm("malicious-ip", "domain|ip", "evil.example|198.51.100.9"), "198.51.100.9")
        self.assertIsNone(self.norm("malicious-ip", "ip-dst", "10.0.0.0/8"))
        self.assertIsNone(self.norm("malicious-ip", "ip-dst", "not-an-ip"))

    def test_domain_and_hash_normalisation(self):
        self.assertEqual(self.norm("malicious-domains", "domain", "Evil.Example."), "evil.example")
        self.assertEqual(self.norm("malicious-domains", "domain|ip", "evil.example|198.51.100.9"), "evil.example")
        self.assertEqual(self.norm("malware-hashes", "filename|sha256", "x.exe|ABCDEF0123"), "abcdef0123")
        self.assertIsNone(self.norm("malware-hashes", "md5", "zzz"))

    def test_cdb_line_quotes_ipv6(self):
        self.assertEqual(self.sync.cdb_line("2001:db8::1", "misp-event-1"), '"2001:db8::1":misp-event-1')
        self.assertEqual(self.sync.cdb_line("198.51.100.77", "misp-event-1"), "198.51.100.77:misp-event-1")

    def test_write_list_only_reports_changes(self):
        self.assertTrue(self.sync.write_list("malicious-ip", {"198.51.100.77": "misp-event-1"}))
        self.assertFalse(self.sync.write_list("malicious-ip", {"198.51.100.77": "misp-event-1"}))
        with open(os.path.join(self.tmp.name, "malicious-ip")) as handle:
            self.assertEqual(handle.read(), "198.51.100.77:misp-event-1\n")

    def test_healthcheck_without_state_fails(self):
        if os.path.exists(os.environ["STATE_FILE"]):
            os.unlink(os.environ["STATE_FILE"])
        self.assertEqual(self.sync.healthcheck(), 1)


if __name__ == "__main__":
    unittest.main()
