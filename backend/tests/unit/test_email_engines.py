import socket
import threading

import httpx
import pytest
import respx

from app.modules.email import engines

pytestmark = pytest.mark.req("EML-06", "EML-07", "EML-08")

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@respx.mock
def test_rspamd_flags_phishing():
    respx.post("http://rspamd:11333/checkv2").mock(return_value=httpx.Response(
        200, json={"action": "reject", "score": 15.0, "required_score": 12.0,
                   "symbols": {"PHISHING": {"score": 7.0}, "DMARC_POLICY_REJECT": {"score": 8.0}}}))
    v = engines.rspamd_check(b"raw email")
    assert v.status == "ok" and v.malicious is True and v.score == 15.0
    assert "PHISHING" in v.details["symbols"]


@respx.mock
def test_rspamd_clean_is_not_malicious():
    respx.post("http://rspamd:11333/checkv2").mock(return_value=httpx.Response(
        200, json={"action": "no action", "score": 1.0, "required_score": 12.0, "symbols": {}}))
    assert engines.rspamd_check(b"raw").malicious is False


def test_rspamd_down_is_not_checked(monkeypatch):
    monkeypatch.setattr(engines, "_rspamd_url", lambda: "http://rspamd-down.invalid:11333")
    v = engines.rspamd_check(b"raw")
    assert v.status == "not_checked"


def _fake_clamd(response: bytes) -> tuple[str, int, threading.Thread]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()

    def serve():
        conn, _ = srv.accept()
        while b"zEND" not in b"":  # drain the INSTREAM upload
            chunk = conn.recv(65536)
            if not chunk or chunk.endswith(b"\x00\x00\x00\x00"):
                break
        conn.sendall(response)
        conn.close()
        srv.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return host, port, t


def test_clamav_detects(monkeypatch):
    host, port, _ = _fake_clamd(b"stream: Eicar-Test-Signature FOUND\x00")
    monkeypatch.setattr(engines, "get_settings", lambda: _settings(host, port))
    v = engines.clamav_scan(EICAR)
    assert v.status == "ok" and v.malicious is True and "Eicar" in v.details["signature"]


def test_clamav_clean(monkeypatch):
    host, port, _ = _fake_clamd(b"stream: OK\x00")
    monkeypatch.setattr(engines, "get_settings", lambda: _settings(host, port))
    v = engines.clamav_scan(b"hello")
    assert v.malicious is False and v.status == "ok"


def test_clamav_disabled(monkeypatch):
    monkeypatch.setattr(engines, "get_settings", lambda: _settings("x", 1, enabled=False))
    assert engines.clamav_scan(b"x").status == "not_checked"


def test_yara_matches_rule(tmp_path, monkeypatch):
    rule = tmp_path / "test.yar"
    rule.write_text('rule phish_marker { strings: $a = "verify your account password" nocase condition: $a }')
    monkeypatch.setattr(engines, "get_settings", lambda: _settings("x", 1, yara_dir=str(tmp_path)))
    engines._yara_rules.cache_clear()
    v = engines.yara_scan(b"Please verify your account password now")
    assert v.malicious is True and "phish_marker" in v.details["matches"]
    assert engines.yara_scan(b"nothing suspicious here").malicious is False


class _settings:
    def __init__(self, host, port, enabled=True, yara_dir="/nonexistent"):
        self.clamav_host, self.clamav_port, self.clamav_enabled = host, port, enabled
        self.yara_rules_dir = yara_dir
        self.rspamd_url = "http://rspamd:11333"
