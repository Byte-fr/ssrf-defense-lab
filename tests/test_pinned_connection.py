import ssl

import pytest
import ip_pinning


APPROVED_HOST = "example.org"
APPROVED_IP = "8.8.8.8"


def test_connection_uses_pinned_ip(monkeypatch):
    captured = {}

    def fake_connection(address, timeout, **kwargs):
        captured["destination"] = address
        raise OSError("Safe test stop")

    monkeypatch.setattr(
        ip_pinning,
        "create_connection",
        fake_connection,
    )

    connection = ip_pinning.PinnedHTTPSConnection(
        host=APPROVED_HOST,
        port=443,
        pinned_ip=APPROVED_IP,
    )

    with pytest.raises(OSError, match="Safe test stop"):
        connection._new_conn()

    assert captured["destination"] == (APPROVED_IP, 443)
    assert connection.host == APPROVED_HOST
    assert connection.pinned_ip == APPROVED_IP
    assert connection.port == 443
    assert connection.cert_reqs == ssl.CERT_REQUIRED
