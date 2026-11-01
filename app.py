from flask import Flask, request, jsonify
from urllib.parse import urlparse
import ipaddress
import socket
import requests
import logging
from logging.handlers import RotatingFileHandler

from ip_pinning import PinnedRequestsAdapter
from threading import BoundedSemaphore

app = Flask(__name__)
fetch_slots = BoundedSemaphore(2)

handler = RotatingFileHandler(
    "security.log",
    maxBytes=1_000_000,
    backupCount=3
)

handler.setLevel(logging.INFO)
handler.setFormatter(
    logging.Formatter("%(asctime)s %(levelname)s %(message)s")
)

app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)



import os

ALLOWED_HOST = os.environ.get("SSRF_ALLOWED_HOST", "").strip().lower()

if not ALLOWED_HOST:
    raise RuntimeError("SSRF_ALLOWED_HOST must be configured")

try:
    config_parts = urlparse("//" + ALLOWED_HOST)
    invalid_host = (
        config_parts.hostname != ALLOWED_HOST
        or config_parts.port is not None
        or bool(config_parts.path)
        or bool(config_parts.query)
        or bool(config_parts.fragment)
    )
except ValueError:
    invalid_host = True

if invalid_host:
    raise RuntimeError(
        "SSRF_ALLOWED_HOST must contain a hostname only, "
        "without a scheme, port, path, query, or fragment"
    )

labels = ALLOWED_HOST.split(".")

if (
    len(ALLOWED_HOST) > 253
    or any(
        not label
        or len(label) > 63
        or not label.isascii()
        or not label[0].isalnum()
        or not label[-1].isalnum()
        or any(
            not (char.isalnum() or char == "-")
            for char in label
        )
        for label in labels
    )
):
    raise RuntimeError(
        "SSRF_ALLOWED_HOST contains an invalid hostname label"
    )


def destination_is_allowed(url):
    try:
        parsed = urlparse(url)

        if parsed.scheme != "https":
            return None

        if parsed.hostname != ALLOWED_HOST:
            return None

        if parsed.username is not None or parsed.password is not None:
            return None

        if parsed.port not in (None, 443):
            return None

        addresses = socket.getaddrinfo(
            parsed.hostname, 443, type=socket.SOCK_STREAM
        )

        if not addresses:
            return None

        approved_ips = []

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            if not ip.is_global:
                return None

            approved_ips.append(str(ip))

        return approved_ips[0]

    except (ValueError, OSError):
        return None

@app.get("/")
def home():
    return "Protected SSRF training lab is running."


@app.get("/fetch")
def fetch_url():
    url = request.args.get("url", "")

    if not fetch_slots.acquire(blocking=False):
        return jsonify(error="Too many requests"), 429

    try:
        pinned_ip = destination_is_allowed(url)

        if not pinned_ip:
            app.logger.warning("SSRF request rejected by URL validation")
            return jsonify(error="URL not allowed"), 403

        try:
            with requests.Session() as session:
                session.trust_env = False

                adapter = PinnedRequestsAdapter(
                    ALLOWED_HOST,
                    pinned_ip
                )

                session.mount("https://", adapter)

                with session.get(
                    url,
                    timeout=3,
                    allow_redirects=False,
                    stream=True
                ) as response:
                    status_code = response.status_code

            app.logger.info(
                "Outbound request completed with status %s",
                status_code
            )

            return jsonify(status_code=status_code)

        except requests.RequestException as exc:
            app.logger.warning(
                "Outbound request failed (%s)",
                type(exc).__name__
            )
            return jsonify(error="Request failed"), 502

    finally:
        fetch_slots.release()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
