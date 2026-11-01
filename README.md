# SSRF Defense Lab

A local Flask-based training project demonstrating practical
Server-Side Request Forgery (SSRF) defenses.

## Security Features

- HTTPS-only destination validation
- Configurable hostname allowlisting
- DNS resolution and public IP validation
- IP-pinned outbound TCP connections
- TLS certificate and hostname verification
- Proxy rejection
- Automatic redirect prevention
- Request timeout configuration
- Concurrent request limiting
- Security event logging

## Project Structure

- `app.py` - Flask application and URL validation
- `ip_pinning.py` - Custom Requests/urllib3 IP-pinning adapter
- `tests/` - Automated test suite

## Requirements

- Python 3.14.8 to python 3.14 (tested on 3.14.8)
- Flask
- Requests
- urllib3

## Installation

Clone the repository and enter its directory:

    git clone <YOUR-REPOSITORY-URL>
    cd ssrf-defense-lab

Create a virtual environment:

    python -m venv venv

Activate it:

    source venv/bin/activate

Install dependencies:

    pip install -r requirements-dev.txt

Configure the allowed hostname:

    export SSRF_ALLOWED_HOST=example.org

Run the application:

    python app.py

The application listens on 127.0.0.1:5000.

## Running Tests

    python -m pytest --cov=app --cov=ip_pinning --cov-report=term-missing

## Security Scope and Limitations

This is a local educational security lab, not a production-ready
SSRF protection service or independently audited security product.

DNS resolution does not currently have an explicit timeout.
Requests' timeout is not a strict total request deadline.
Production deployments require additional controls, including
network-level egress restrictions and deployment hardening.

## License

To be determined.
