"""
Shared secure network execution wrapper for Phase 10A Passive Adapters.

Enforces:
1. Exact destination allowlist (exact hostname match required)
2. HTTPS-only policy
3. Redirect protection (revalidating every redirect destination against exact allowlist & SSRF checks)
4. DNS / SSRF & Private IP protection (blocking localhost, loopback, link-local, RFC1918, cloud metadata)
5. Short request timeout
6. Maximum response size cap
7. Centralized rate limiting and max_concurrent enforcement
8. Fail-closed error handling
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

from ctf_mentor.tools.contracts import RateLimitPolicy

logger = logging.getLogger(__name__)


class NetworkSecurityError(Exception):
    """Base exception for network security violations."""
    pass


class SSRFProtectionError(NetworkSecurityError):
    """Raised when an IP or hostname violates SSRF / private range policy."""
    pass


class RedirectSecurityError(NetworkSecurityError):
    """Raised when a redirect target violates destination allowlist or security policy."""
    pass


class ResponseSizeExceededError(NetworkSecurityError):
    """Raised when response body exceeds max allowed bytes."""
    pass


class RateLimitExceededError(NetworkSecurityError):
    """Raised when request frequency exceeds rate limit policy."""
    pass


class ConcurrencyLimitExceededError(RateLimitExceededError):
    """Raised when active concurrent requests exceed max_concurrent threshold."""
    pass


# Forbidden IP networks for SSRF protection
FORBIDDEN_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # IPv4 loopback
    ipaddress.ip_network("10.0.0.0/8"),        # Private RFC1918
    ipaddress.ip_network("172.16.0.0/12"),     # Private RFC1918
    ipaddress.ip_network("192.168.0.0/16"),    # Private RFC1918
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local & cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),         # Current network
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique local
]

FORBIDDEN_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "169.254.169.254",
}


def is_forbidden_ip(ip_str: str) -> bool:
    """Check if an IP string belongs to any forbidden private/loopback/link-local network."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        # Not an IP literal address string (e.g. domain name)
        return False

    for net in FORBIDDEN_NETWORKS:
        if ip_obj in net:
            return True
    return False


def resolve_and_validate_host(hostname: str, port: int = 443) -> List[str]:
    """Resolve hostname via DNS and validate resolved IPs against forbidden networks.

    Fails closed if hostname is in forbidden hostnames, cannot be resolved,
    or resolves to any forbidden IP address.
    """
    clean_host = hostname.strip().lower().rstrip(".")
    if clean_host in FORBIDDEN_HOSTNAMES:
        raise SSRFProtectionError(f"Forbidden hostname blocked: {clean_host!r}")

    # Check IP literal strings
    if is_forbidden_ip(clean_host):
        raise SSRFProtectionError(f"Forbidden IP address blocked: {clean_host!r}")

    # Perform DNS resolution
    try:
        addr_info = socket.getaddrinfo(clean_host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SSRFProtectionError(f"DNS resolution failed for hostname {clean_host!r}: {e}")

    resolved_ips: List[str] = []
    for family, socktype, proto, canonname, sockaddr in addr_info:
        ip_addr = sockaddr[0]
        if is_forbidden_ip(ip_addr):
            raise SSRFProtectionError(
                f"Hostname {clean_host!r} resolved to forbidden IP address {ip_addr!r}"
            )
        resolved_ips.append(ip_addr)

    if not resolved_ips:
        raise SSRFProtectionError(f"No IP addresses resolved for hostname {clean_host!r}")

    return resolved_ips


class SimpleRateLimiter:
    """In-memory sliding window rate limiter."""

    def __init__(self) -> None:
        self._history: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def check_and_record(self, key: str, max_requests: int, window_seconds: float) -> bool:
        now = time.time()
        cutoff = now - window_seconds
        with self._lock:
            timestamps = self._history.get(key, [])
            timestamps = [t for t in timestamps if t > cutoff]
            if len(timestamps) >= max_requests:
                self._history[key] = timestamps
                return False
            timestamps.append(now)
            self._history[key] = timestamps
            return True


class SimpleConcurrencyTracker:
    """Thread-safe active concurrency tracker per context key."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active: Dict[str, int] = {}

    def acquire(self, key: str, max_concurrent: int) -> bool:
        with self._lock:
            current = self._active.get(key, 0)
            if current >= max_concurrent:
                return False
            self._active[key] = current + 1
            return True

    def release(self, key: str) -> None:
        with self._lock:
            current = self._active.get(key, 0)
            if current > 1:
                self._active[key] = current - 1
            elif key in self._active:
                del self._active[key]


# Global rate limiter and concurrency tracker instances
_global_rate_limiter = SimpleRateLimiter()
_global_concurrency_tracker = SimpleConcurrencyTracker()


class SecureNetworkWrapper:
    """Shared secure network request runner enforcing allowlists, SSRF protection,

    HTTPS policy, redirect revalidation, timeouts, max response sizes, and max_concurrent limits.
    """

    def __init__(
        self,
        allowed_destinations: List[str],
        rate_limit_policy: Optional[RateLimitPolicy] = None,
        transport_mock: Optional[Callable[[str, Dict[str, str]], Tuple[int, Dict[str, str], bytes]]] = None,
    ) -> None:
        self.allowed_destinations = [d.strip().lower().rstrip(".") for d in allowed_destinations]
        self.rate_limit_policy = rate_limit_policy or RateLimitPolicy()
        self.transport_mock = transport_mock

    def _validate_destination(self, url: str) -> Tuple[str, str, int, str]:
        """Parse URL, validate scheme (HTTPS), exact destination allowlist, and resolve IP.

        Returns (scheme, host, port, path_and_query).
        """
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme != "https":
            raise NetworkSecurityError(f"Insecure scheme {scheme!r}; only HTTPS is allowed.")

        host = (parsed.hostname or "").strip().lower().rstrip(".")
        if not host:
            raise NetworkSecurityError(f"Invalid URL: missing hostname in {url!r}")

        port = parsed.port or (443 if scheme == "https" else 80)

        # Check exact destination allowlist (subdomains NOT implicitly allowed unless listed)
        allowed = False
        for allowed_dest in self.allowed_destinations:
            allowed_clean = allowed_dest.strip().lower().rstrip(".")
            if host == allowed_clean:
                allowed = True
                break
        if not allowed:
            raise RedirectSecurityError(
                f"Destination {host!r} is not in exact authorized network allowlist: {self.allowed_destinations}"
            )

        # DNS resolution & SSRF protection
        if not self.transport_mock:
            resolve_and_validate_host(host, port)
        else:
            if clean_host := host.rstrip("."):
                if clean_host in FORBIDDEN_HOSTNAMES or is_forbidden_ip(clean_host):
                    raise SSRFProtectionError(f"Forbidden host blocked: {clean_host!r}")

        path_and_query = parsed.path or "/"
        if parsed.query:
            path_and_query += "?" + parsed.query

        return scheme, host, port, path_and_query

    def request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        context_key: str = "global",
    ) -> Tuple[int, Dict[str, str], bytes]:
        """Execute a secure network request with redirect revalidation, concurrency enforcement, and response bounds."""
        # 1. Enforce Rate Limiting (window limit)
        if not _global_rate_limiter.check_and_record(
            key=context_key,
            max_requests=self.rate_limit_policy.max_requests_per_window,
            window_seconds=self.rate_limit_policy.window_seconds,
        ):
            raise RateLimitExceededError(
                f"Rate limit of {self.rate_limit_policy.max_requests_per_window} requests per "
                f"{self.rate_limit_policy.window_seconds}s exceeded for {context_key!r}"
            )

        # 2. Enforce Concurrency Limit
        if not _global_concurrency_tracker.acquire(context_key, self.rate_limit_policy.max_concurrent):
            raise ConcurrencyLimitExceededError(
                f"Concurrency limit of {self.rate_limit_policy.max_concurrent} active requests "
                f"exceeded for context {context_key!r}"
            )

        try:
            current_url = url
            max_redirects = 3
            redirect_count = 0

            while True:
                # Validate destination & SSRF checks for current URL (exact allowlist check)
                scheme, host, port, path_and_query = self._validate_destination(current_url)

                # Use transport mock if provided (e.g. in tests)
                if self.transport_mock:
                    status, resp_headers, resp_bytes = self.transport_mock(current_url, headers or {})
                else:
                    # Standard Python urllib request execution with manual redirect handling
                    req = urllib.request.Request(
                        current_url,
                        data=body,
                        headers=headers or {},
                        method=method.upper(),
                    )
                    try:
                        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                            def redirect_request(self, req, fp, code, msg, headers, newurl):
                                return None

                        opener = urllib.request.build_opener(NoRedirectHandler)
                        with opener.open(req, timeout=self.rate_limit_policy.timeout_seconds) as resp:
                            status = resp.status
                            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                            resp_bytes = resp.read(self.rate_limit_policy.max_response_bytes + 1)
                    except urllib.error.HTTPError as http_err:
                        status = http_err.code
                        resp_headers = {k.lower(): v for k, v in http_err.headers.items()}
                        resp_bytes = http_err.read(self.rate_limit_policy.max_response_bytes + 1)
                    except Exception as ex:
                        raise NetworkSecurityError(f"Network request to {host!r} failed: {ex}")

                # Check response size cap
                if len(resp_bytes) > self.rate_limit_policy.max_response_bytes:
                    raise ResponseSizeExceededError(
                        f"Response size {len(resp_bytes)} bytes exceeded maximum threshold of "
                        f"{self.rate_limit_policy.max_response_bytes} bytes."
                    )

                # Handle redirects manually with exact allowlist revalidation
                if status in (301, 302, 303, 307, 308):
                    redirect_count += 1
                    if redirect_count > max_redirects:
                        raise RedirectSecurityError("Too many redirects (exceeded limit of 3)")

                    location = resp_headers.get("location")
                    if not location:
                        raise RedirectSecurityError("Redirect status code received without Location header")

                    # Resolve relative redirect URLs
                    new_url = urllib.parse.urljoin(current_url, location)
                    logger.info(f"Following revalidated redirect: {current_url} -> {new_url}")
                    current_url = new_url
                    continue

                return status, resp_headers, resp_bytes
        finally:
            _global_concurrency_tracker.release(context_key)
