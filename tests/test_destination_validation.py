import os
import socket

import pytest

os.environ.setdefault("SSRF_ALLOWED_HOST", "example.org")

import app


def make_dns_result(ip):
    return (
        socket.AF_INET,
        socket.SOCK_STREAM,
        6,
        "",
        (ip, 443),
    )


def test_accepts_public_ip(monkeypatch):
    monkeypatch.setattr(
        app.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            make_dns_result("8.8.8.8")
        ],
    )

    url = f"https://{app.ALLOWED_HOST}/"

    assert app.destination_is_allowed(url) == "8.8.8.8"


def test_rejects_private_ip(monkeypatch):
    monkeypatch.setattr(
        app.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            make_dns_result("192.168.1.10")
        ],
    )

    url = f"https://{app.ALLOWED_HOST}/"

    assert app.destination_is_allowed(url) is None


def test_rejects_mixed_public_and_private_ips(monkeypatch):
    monkeypatch.setattr(
        app.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            make_dns_result("8.8.8.8"),
            make_dns_result("192.168.1.10"),
        ],
    )

    url = f"https://{app.ALLOWED_HOST}/"

    assert app.destination_is_allowed(url) is None


def test_rejects_empty_dns_response(monkeypatch):
    monkeypatch.setattr(
        app.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [],
    )

    url = f"https://{app.ALLOWED_HOST}/"

    assert app.destination_is_allowed(url) is None


def test_rejects_dns_resolution_error(monkeypatch):
    def failed_dns(*args, **kwargs):
        raise socket.gaierror("Simulated DNS failure")

    monkeypatch.setattr(
        app.socket,
        "getaddrinfo",
        failed_dns,
    )

    url = f"https://{app.ALLOWED_HOST}/"

    assert app.destination_is_allowed(url) is None


def test_rejects_unapproved_hostname():
    assert (
        app.destination_is_allowed("https://not-allowed.example/")
        is None
    )


def test_rejects_http_scheme():
    url = f"http://{app.ALLOWED_HOST}/"

    assert app.destination_is_allowed(url) is None

def test_rejects_url_with_credentials():
    url = f"https://user:password@{app.ALLOWED_HOST}/"
    assert app.destination_is_allowed(url) is None


def test_rejects_nonstandard_port():
    url = f"https://{app.ALLOWED_HOST}:8443/"
    assert app.destination_is_allowed(url) is None


def test_rejects_malformed_port():
    url = f"https://{app.ALLOWED_HOST}:invalid/"
    assert app.destination_is_allowed(url) is None
