import ipaddress

from urllib.parse import urlsplit

from requests.adapters import HTTPAdapter
from requests.exceptions import InvalidURL, ProxyError, SSLError
from requests.utils import select_proxy

from urllib3 import HTTPSConnectionPool
from urllib3.connection import HTTPSConnection
from urllib3.util.connection import create_connection


class PinnedHTTPSConnection(HTTPSConnection):
    def __init__(self, *args, pinned_ip, **kwargs):
        self.pinned_ip = str(ipaddress.ip_address(pinned_ip))
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        return create_connection(
            (self.pinned_ip, self.port),
            self.timeout,
            source_address=self.source_address,
            socket_options=self.socket_options,
        )


class PinnedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = PinnedHTTPSConnection

    def __init__(self, host, pinned_ip, port=443, **kwargs):
        self.pinned_ip = str(ipaddress.ip_address(pinned_ip))

        super().__init__(
            host=host,
            port=port,
            maxsize=1,
            block=True,
            **kwargs,
            pinned_ip=self.pinned_ip,
        )

class PinnedRequestsAdapter(HTTPAdapter):
    def __init__(self, allowed_host, pinned_ip):
        self.allowed_host = allowed_host.lower()
        self.pinned_ip = str(ipaddress.ip_address(pinned_ip))

        super().__init__(
            pool_connections=1,
            pool_maxsize=1,
            max_retries=0,
            pool_block=True,
        )

        self.pinned_pool = PinnedHTTPSConnectionPool(
            host=self.allowed_host,
            pinned_ip=self.pinned_ip,
            port=443,
        )

    def get_connection_with_tls_context(
        self, request, verify, proxies=None, cert=None
    ):
        if verify is False:
            raise SSLError("TLS certificate verification cannot be disabled")

        if select_proxy(request.url, proxies):
            raise ProxyError("Proxies are not permitted")

        try:
            parsed = urlsplit(request.url)
            port = parsed.port
        except ValueError as exc:
            raise InvalidURL("Invalid destination URL") from exc

        if (
            parsed.scheme.lower() != "https"
            or parsed.hostname != self.allowed_host
            or port not in (None, 443)
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise InvalidURL("Destination does not match the pinned host")

        return self.pinned_pool

    def close(self):
        self.pinned_pool.close()
        super().close()
