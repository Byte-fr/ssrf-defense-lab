import os
import subprocess
import sys


def run_app_with_host(host):
    env = os.environ.copy()

    if host is None:
        env.pop("SSRF_ALLOWED_HOST", None)
    else:
        env["SSRF_ALLOWED_HOST"] = host

    return subprocess.run(
        [sys.executable, "-c", "import app"],
        capture_output=True,
        text=True,
        env=env,
    )


def test_rejects_missing_allowed_host():
    result = run_app_with_host(None)

    assert result.returncode != 0
    assert "SSRF_ALLOWED_HOST must be configured" in result.stderr


def test_rejects_hostname_with_scheme():
    result = run_app_with_host("https://example.org")

    assert result.returncode != 0
    assert "hostname only" in result.stderr


def test_rejects_hostname_with_port():
    result = run_app_with_host("example.org:8443")

    assert result.returncode != 0
    assert "hostname only" in result.stderr


def test_rejects_malformed_bracketed_hostname():
    result = run_app_with_host("[invalid")

    assert result.returncode != 0
    assert "hostname only" in result.stderr


def test_rejects_invalid_hostname_label():
    result = run_app_with_host("-invalid.example")

    assert result.returncode != 0
    assert "invalid hostname label" in result.stderr
