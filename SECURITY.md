# Security Policy

## Project Scope

SSRF Defense Lab is a local educational project demonstrating
defensive techniques against Server-Side Request Forgery (SSRF).

It is not intended for production deployment.

## Security Controls

The application currently implements:

- HTTPS-only destination validation.
- Configurable hostname allowlisting.
- DNS resolution and public IP validation.
- IP-pinned outbound TCP connections.
- TLS certificate and hostname verification.
- Proxy rejection.
- Automatic redirect prevention.
- Request timeouts.
- Concurrent request limiting.
- Security event logging.

## Known Limitations

- DNS resolution does not have an explicit timeout.
- Requests' timeout is not a strict total request deadline.
- The concurrency limit is process-local.
- Flask's development server is not suitable for production.
- Application-level validation should be supported by
  network-level outbound traffic restrictions.

## Reporting Security Issues

If you discover a security issue in this educational project,
please report it privately to the repository owner.

Include the affected component, steps to reproduce the issue,
and its potential security impact.

Please avoid publishing sensitive exploit details before
the issue has been reviewed.
