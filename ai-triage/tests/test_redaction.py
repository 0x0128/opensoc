from __future__ import annotations

import json

import pytest

from ai_triage.security.redaction import PIIRedactor, iban_valid, luhn_valid, spanish_id_valid

from .helpers import load_alert


def redactor(**kwargs: object) -> PIIRedactor:
    kwargs.setdefault("keep_usernames", ["root", "admin"])
    return PIIRedactor(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("login from maria.lopez@example.org", "maria.lopez@example.org"),
        ("card 4111 1111 1111 1111 used", "4111 1111 1111 1111"),
        ("card 5500-0000-0000-0004 used", "5500-0000-0000-0004"),
        ("IBAN ES9121000418450200051332", "ES9121000418450200051332"),
        ("DNI 12345678Z", "12345678Z"),
        ("NIE X1234567L", "X1234567L"),
        ("ssn 123-45-6789", "123-45-6789"),
        ("call +34 612 345 678 now", "+34 612 345 678"),
        ("mac 00:1a:2b:3c:4d:5e seen", "00:1a:2b:3c:4d:5e"),
        ("src 185.220.101.47 port 22", "185.220.101.47"),
        ("src 2a01:4f8:c010:d56::2 port 22", "2a01:4f8:c010:d56::2"),
        ("password=hunter2&x=1", "hunter2"),
        ("pwd: 'my secret pass'", "my secret pass"),
        ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"),
        ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlMTIz", "eyJhbGciOiJIUzI1NiJ9"),
        ("aws AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
        ("git https://bob:s3cr3t@git.example.com/repo", "s3cr3t"),
        ("key sk-ant-api03-abcdefghijklmnopqrstuvwx", "sk-ant-api03-abcdefghijklmnopqrstuvwx"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", "MIIEow"),
        ("user=mgarcia logged in", "mgarcia"),
    ],
)
def test_sensitive_values_are_removed(text: str, secret: str) -> None:
    assert secret not in redactor().redact_text(text)


@pytest.mark.parametrize(
    "text",
    [
        "time 10:30:45 ok",
        "Wazuh alert 1762247564.4471",
        "epoch 1700000000123 ms",
        "loopback 127.0.0.1 and ::1",
        "version 2.4.41",
        "Failed password for root from host",
        "card 4111 1111 1111 1112 (fails Luhn)",
        "DNI 12345678A (wrong letter)",
    ],
)
def test_non_pii_is_preserved(text: str) -> None:
    assert redactor().redact_text(text) == text


def test_ip_classification_and_stable_placeholders() -> None:
    r = redactor()
    out = r.redact_text("from 185.220.101.47 to 10.0.0.5, again 185.220.101.47 and 192.168.1.9")
    assert out == "from [IP_EXTERNAL_1] to [IP_INTERNAL_1], again [IP_EXTERNAL_1] and [IP_INTERNAL_2]"
    assert r.counts == {"IP_EXTERNAL": 1, "IP_INTERNAL": 2}


def test_ip_redaction_can_be_disabled() -> None:
    assert "185.220.101.47" in PIIRedactor(redact_ips=False).redact_text("from 185.220.101.47")


def test_structure_redaction_by_key_and_propagation_to_free_text() -> None:
    alert = load_alert("ssh_bruteforce")
    alert["data"]["srcuser"] = "jdoe"
    alert["full_log"] = "Invalid user jdoe from 185.220.101.47 port 51544"
    r = redactor()
    out = r.redact(alert)
    assert out["data"]["srcuser"] == "[USER_1]"
    assert out["full_log"] == "Invalid user [USER_1] from [IP_EXTERNAL_1] port 51544"
    assert out["agent"]["ip"] == "[IP_INTERNAL_1]"
    assert out["agent"]["name"] == "web-prod-01"  # hostnames are kept for context


def test_well_known_system_accounts_are_kept() -> None:
    out = redactor().redact({"data": {"dstuser": "root"}, "full_log": "session opened for user root"})
    assert out["data"]["dstuser"] == "root"
    assert "root" in out["full_log"]


def test_windows_and_whodata_user_fields() -> None:
    r = redactor()
    out = r.redact(
        {
            "data": {"win": {"eventdata": {"targetUserName": "CORP\\mgarcia"}}},
            "syscheck": {"audit": {"user": {"name": "jsmith", "id": "1001"}}},
            "full_log": "mgarcia changed file as jsmith",
        }
    )
    assert out["data"]["win"]["eventdata"]["targetUserName"] == "[USER_1]"
    assert out["syscheck"]["audit"]["user"]["name"] == "[USER_2]"
    assert out["full_log"] == "[USER_1] changed file as [USER_2]"


def test_secret_keys_are_never_reversible() -> None:
    r = redactor()
    out = r.redact({"data": {"password": "Sup3rS3cret!", "token": 12345}})
    assert out["data"] == {"password": "[REDACTED_SECRET]", "token": "[REDACTED_SECRET]"}
    assert r.rehydrate("[REDACTED_SECRET]") == "[REDACTED_SECRET]"


def test_extra_user_keys_are_configurable() -> None:
    out = PIIRedactor(extra_user_keys=["operator_id"]).redact({"data": {"operator_id": "op-7781"}})
    assert out["data"]["operator_id"] == "[USER_1]"


def test_rehydration_restores_only_reversible_placeholders() -> None:
    r = redactor()
    r.redact({"data": {"srcip": "185.220.101.47", "dstuser": "jdoe"}, "full_log": "card 4111111111111111"})
    restored = r.rehydrate("Block [IP_EXTERNAL_1], reset [USER_1], card [CARD_1], unknown [USER_9]")
    assert restored == "Block 185.220.101.47, reset jdoe, card [CARD_1], unknown [USER_9]"


def test_pii_fixture_is_fully_redacted() -> None:
    alert = load_alert("pii_auth")
    out = json.dumps(redactor().redact(alert))
    for value in ["maria.lopez@example.org", "12345678Z", "612 345 678", "203.0.113.77", "4111 1111",
                  "Sup3rS3cret!", "eyJhbGciOiJIUzI1NiJ9", "mlopez", "192.168.10.44"]:  # fmt: skip
        assert value not in out, value


def test_validators() -> None:
    assert luhn_valid("4111111111111111") and not luhn_valid("4111111111111112")
    assert iban_valid("ES91 2100 0418 4502 0005 1332") and not iban_valid("ES00 2100 0418 4502 0005 1332")
    assert spanish_id_valid("12345678Z") and spanish_id_valid("X1234567L") and not spanish_id_valid("12345678A")
