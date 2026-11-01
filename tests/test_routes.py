import os

os.environ.setdefault("SSRF_ALLOWED_HOST", "example.org")

import requests
import app


def test_home_route():
    client = app.app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert response.get_data(as_text=True) == (
        "Protected SSRF training lab is running."
    )


def test_fetch_rejects_invalid_destination(monkeypatch):
    monkeypatch.setattr(
        app,
        "destination_is_allowed",
        lambda url: None,
    )

    client = app.app.test_client()
    response = client.get("/fetch?url=https://evil.example/")

    assert response.status_code == 403
    assert response.get_json() == {"error": "URL not allowed"}


def test_fetch_returns_429_when_capacity_is_full(monkeypatch):
    class FullSemaphore:
        def acquire(self, blocking=False):
            return False

    monkeypatch.setattr(app, "fetch_slots", FullSemaphore())

    client = app.app.test_client()
    response = client.get("/fetch?url=https://example.org/")

    assert response.status_code == 429
    assert response.get_json() == {"error": "Too many requests"}


def test_fetch_returns_502_on_upstream_failure(monkeypatch):
    monkeypatch.setattr(
        app,
        "destination_is_allowed",
        lambda url: "8.8.8.8",
    )

    class FailingSession:
        trust_env = True

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def mount(self, prefix, adapter):
            pass

        def get(self, *args, **kwargs):
            raise requests.ConnectionError("Simulated connection failure")

    monkeypatch.setattr(app.requests, "Session", FailingSession)
    monkeypatch.setattr(
        app,
        "PinnedRequestsAdapter",
        lambda *args: object(),
    )

    client = app.app.test_client()
    response = client.get("/fetch?url=https://example.org/")

    assert response.status_code == 502
    assert response.get_json() == {"error": "Request failed"}

    assert app.fetch_slots.acquire(blocking=False)
    app.fetch_slots.release()

def test_fetch_returns_upstream_status(monkeypatch):
    monkeypatch.setattr(
        app,
        "destination_is_allowed",
        lambda url: "8.8.8.8",
    )

    class FakeResponse:
        status_code = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    class SuccessfulSession:
        trust_env = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def mount(self, prefix, adapter):
            pass

        def get(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setattr(
        app.requests,
        "Session",
        SuccessfulSession,
    )

    monkeypatch.setattr(
        app,
        "PinnedRequestsAdapter",
        lambda *args: object(),
    )

    client = app.app.test_client()
    response = client.get("/fetch?url=https://example.org/")

    assert response.status_code == 200
    assert response.get_json() == {"status_code": 200}

def test_fetch_disables_redirects(monkeypatch):
    monkeypatch.setattr(
        app,
        "destination_is_allowed",
        lambda url: "8.8.8.8",
    )

    captured = {}

    class FakeResponse:
        status_code = 302

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    class FakeSession:
        trust_env = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def mount(self, prefix, adapter):
            pass

        def get(self, url, **kwargs):
            captured.update(kwargs)
            return FakeResponse()

    monkeypatch.setattr(app.requests, "Session", FakeSession)
    monkeypatch.setattr(
        app,
        "PinnedRequestsAdapter",
        lambda *args: object(),
    )

    client = app.app.test_client()
    response = client.get("/fetch?url=https://example.org/")

    assert response.status_code == 200
    assert response.get_json() == {"status_code": 302}
    assert captured["allow_redirects"] is False
