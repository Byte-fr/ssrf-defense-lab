import ssl

import ip_pinning
import urllib3.connection


APPROVED_HOST = "example.org"
APPROVED_IP = "8.8.8.8"


class FakeSocket:
    def close(self):
        pass


def test_pinned_ip_preserves_tls_hostname(monkeypatch):
    captured = {}

    def fake_create_connection(address, *args, **kwargs):
        captured["tcp_destination"] = address
        return FakeSocket()

    def fake_tls_wrap(*args, **kwargs):
        captured["tls_hostname"] = kwargs.get("server_hostname")
        captured["certificate_requirement"] = kwargs.get("cert_reqs")
        return FakeSocket(), True

    monkeypatch.setattr(
        ip_pinning,
        "create_connection",
        fake_create_connection,
    )

    monkeypatch.setattr(
        urllib3.connection,
        "_ssl_wrap_socket_and_match_hostname",
        fake_tls_wrap,
    )

    connection = ip_pinning.PinnedHTTPSConnection(
        host=APPROVED_HOST,
        port=443,
        pinned_ip=APPROVED_IP,
    )

    connection.cert_reqs = ssl.CERT_REQUIRED
    connection.connect()

    assert captured["tcp_destination"] == (APPROVED_IP, 443)
    assert captured["tls_hostname"] == APPROVED_HOST
    assert captured["certificate_requirement"] == ssl.CERT_REQUIRED
