from types import SimpleNamespace

import pytest
import requests


from requests.exceptions import InvalidURL, ProxyError, SSLError

from ip_pinning import PinnedRequestsAdapter


APPROVED_HOST = "example.org"
APPROVED_IP = "8.8.8.8"


@pytest.fixture
def adapter():
    instance = PinnedRequestsAdapter(APPROVED_HOST, APPROVED_IP)
    yield instance
    instance.close()


def prepare_request(url):
    return requests.Request("GET", url).prepare()


def test_adapter_accepts_approved_destination(adapter):
    request = prepare_request("https://example.org/")

    connection = adapter.get_connection_with_tls_context(
        request, verify=True
    )

    assert connection is adapter.pinned_pool



def test_adapter_rejects_malformed_port(adapter):
    request = SimpleNamespace(
        url="https://example.org:invalid/"
    )

    with pytest.raises(InvalidURL, match="Invalid destination URL"):
        adapter.get_connection_with_tls_context(
            request, verify=True
        )

def test_adapter_rejects_proxy(adapter):
    request = prepare_request("https://example.org/")

    with pytest.raises(ProxyError):
        adapter.get_connection_with_tls_context(
            request,
            verify=True,
            proxies={"https": "http://127.0.0.1:8080"},
        )


def test_adapter_rejects_wrong_hostname(adapter):
    request = prepare_request("https://evil.example/")

    with pytest.raises(InvalidURL):
        adapter.get_connection_with_tls_context(
            request, verify=True
        )


def test_adapter_rejects_http_scheme(adapter):
    request = prepare_request("http://example.org/")

    with pytest.raises(InvalidURL):
        adapter.get_connection_with_tls_context(
            request, verify=True
        )


def test_adapter_rejects_nonstandard_port(adapter):
    request = prepare_request("https://example.org:8443/")

    with pytest.raises(InvalidURL):
        adapter.get_connection_with_tls_context(
            request, verify=True
        )


def test_adapter_rejects_url_credentials(adapter):
    request = prepare_request(
        "https://user:password@example.org/"
    )

    with pytest.raises(InvalidURL):
        adapter.get_connection_with_tls_context(
            request, verify=True
        )


def test_adapter_rejects_disabled_tls_verification(adapter):
    request = prepare_request("https://example.org/")

    with pytest.raises(
        SSLError,
        match="TLS certificate verification cannot be disabled"
    ):
        adapter.get_connection_with_tls_context(
            request, verify=False
        )
