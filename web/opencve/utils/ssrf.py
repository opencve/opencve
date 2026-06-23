"""
SSRF protection for user-controlled outbound HTTP URLs.
"""

import ipaddress
import socket
import threading
from contextlib import contextmanager
from urllib.parse import urljoin, urlparse

import requests

MAX_REDIRECTS = 3
DEFAULT_TIMEOUT = (5, 30)
REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})
ALLOWED_SCHEMES = frozenset({"http", "https"})
BLOCKED_HOSTNAMES = frozenset({"localhost", "0"})
CLOUD_METADATA_HOST = "169.254.169.254"
UNIQUE_LOCAL_IPV6 = ipaddress.ip_network("fc00::/7")

_pin_state = threading.local()
_real_getaddrinfo = socket.getaddrinfo


class UnsafeURL(Exception):
    """Raised when a user-controlled URL targets a forbidden destination."""


def _guarded_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    """Thread-local getaddrinfo wrapper: pinned hostnames skip fresh DNS (any port)."""
    pin = getattr(_pin_state, "pin", None)
    if pin is not None:
        if _normalize_hostname(host) == pin["hostname"]:
            results = pin["results"]
            if family == 0:
                return results
            filtered = [result for result in results if result[0] == family]
            return filtered or results
    return _real_getaddrinfo(host, port, family, type, proto, flags)


# Applied once at import; see module docstring for ordering constraints.
if socket.getaddrinfo is _real_getaddrinfo:
    socket.getaddrinfo = _guarded_getaddrinfo


def _normalize_hostname(hostname):
    """Normalize a hostname for blocklist and DNS pin comparisons."""
    return hostname.rstrip(".").lower()


def _default_port(scheme, port):
    """Return the explicit port or the default for the scheme."""
    if port is not None:
        return port
    return 443 if scheme == "https" else 80


def _host_header(hostname, port, scheme):
    """Build the HTTP Host header value for a pinned request."""
    default_port = 443 if scheme == "https" else 80
    if port and port != default_port:
        return f"{hostname}:{port}"
    return hostname


def _is_blocked_ip(ip):
    """Return True when an IP is private, reserved or otherwise disallowed."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip in UNIQUE_LOCAL_IPV6:
            return True
        mapped = ip.ipv4_mapped
        if mapped is not None:
            ip = mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _validate_ip(ip):
    """Raise UnsafeURL when the IP is not a safe public target."""
    if _is_blocked_ip(ip):
        raise UnsafeURL("URL targets a private or reserved address")


def _looks_like_ip_shorthand(hostname):
    """Return True for decimal, hex or octal IP encodings not parsed by ipaddress."""
    if hostname.isdigit():
        return True
    if hostname.startswith("0x"):
        return True
    if hostname.count(".") == 3 and all(part.isdigit() for part in hostname.split(".")):
        return any(
            len(part) > 1 and part.startswith("0") for part in hostname.split(".")
        )
    return False


def _validate_hostname(hostname):
    """Reject blocked hostnames and non-standard IP literal shorthands."""
    normalized = _normalize_hostname(hostname)
    if normalized in BLOCKED_HOSTNAMES:
        raise UnsafeURL("URL targets a private or reserved address")
    if normalized == CLOUD_METADATA_HOST:
        raise UnsafeURL("URL targets a private or reserved address")
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        if _looks_like_ip_shorthand(normalized):
            raise UnsafeURL("URL targets a private or reserved address")


def _resolve_validated_ips(hostname, port):
    """Resolve a hostname and return its validated public IP addresses."""
    try:
        addrinfo = _real_getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise UnsafeURL("URL hostname could not be resolved") from exc

    if not addrinfo:
        raise UnsafeURL("URL hostname could not be resolved")

    validated_ips = []
    seen = set()
    for result in addrinfo:
        ip_str = result[4][0]
        if ip_str in seen:
            continue
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        _validate_ip(ip)
        seen.add(ip_str)
        validated_ips.append(ip_str)

    if not validated_ips:
        raise UnsafeURL("URL hostname could not be resolved")

    validated_ips.sort(key=lambda ip: ":" in ip)
    return validated_ips


def _parse_and_validate_url(url):
    """Parse a URL and return validated connection metadata and pinned IPs."""
    parsed = urlparse(url)

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeURL("URL scheme is not allowed")

    if not parsed.hostname:
        raise UnsafeURL("URL must include a hostname")

    if parsed.username or parsed.password:
        raise UnsafeURL("URL credentials are not allowed")

    try:
        port = parsed.port
    except ValueError as exc:
        raise UnsafeURL("URL port is not valid") from exc
    if port is not None and not (1 <= port <= 65535):
        raise UnsafeURL("URL port is not valid")

    hostname = parsed.hostname.rstrip(".")
    _validate_hostname(hostname)

    connect_port = _default_port(scheme, port)
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        pinned_ips = _resolve_validated_ips(hostname, connect_port)
    else:
        _validate_ip(ip)
        pinned_ips = [str(ip)]

    return parsed, hostname, connect_port, pinned_ips


def validate_public_http_url(url):
    """
    Validate that url is a safe public HTTP/HTTPS target.

    Raises UnsafeURL when the URL is not allowed.
    """
    _parse_and_validate_url(url)


def _pin_results(hostname, port, pinned_ips):
    """Build getaddrinfo-style results from pre-validated IP addresses."""
    results = []
    for ip in pinned_ips:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        results.append((family, socket.SOCK_STREAM, 6, "", (ip, port)))
    return results


@contextmanager
def _pin_dns(hostname, port, pinned_ips):
    """
    Force DNS lookups on this thread to return only pre-validated IPs.

    Prevents DNS rebinding between validation and connect (TOCTOU).
    """
    results = _pin_results(hostname, port, pinned_ips)
    _pin_state.pin = {
        "hostname": _normalize_hostname(hostname),
        "port": port,
        "results": results,
    }
    try:
        yield
    finally:
        _pin_state.pin = None


def _request_with_pinned_dns(
    session, method, url, pinned_ips, hostname, port, **kwargs
):
    """Send an HTTP request with DNS pinning and an explicit Host header."""
    headers = dict(kwargs.pop("headers", None) or {})
    parsed = urlparse(url)
    headers["Host"] = _host_header(hostname, parsed.port, parsed.scheme)

    with _pin_dns(hostname, port, pinned_ips):
        return session.request(
            method,
            url,
            allow_redirects=False,
            headers=headers,
            **kwargs,
        )


def safe_request(method, url, **kwargs):
    """
    Perform an HTTP request to a user-controlled URL with SSRF protections.

    Redirects are followed manually (max MAX_REDIRECTS) with revalidation at each hop.
    """
    timeout = kwargs.pop("timeout", DEFAULT_TIMEOUT)
    request_kwargs = {
        "headers": kwargs.pop("headers", None),
        "json": kwargs.pop("json", None),
        "data": kwargs.pop("data", None),
    }
    request_kwargs = {
        key: value for key, value in request_kwargs.items() if value is not None
    }
    if kwargs:
        raise TypeError(f"Unexpected keyword arguments: {', '.join(sorted(kwargs))}")

    current_url = url
    redirects = 0

    session = requests.Session()
    session.trust_env = False
    try:
        while True:
            parsed, hostname, connect_port, pinned_ips = _parse_and_validate_url(
                current_url
            )
            response = _request_with_pinned_dns(
                session,
                method,
                current_url,
                pinned_ips,
                hostname,
                connect_port,
                timeout=timeout,
                **request_kwargs,
            )

            if response.status_code not in REDIRECT_STATUS_CODES:
                return response

            location = response.headers.get("Location")
            if not location:
                return response

            redirects += 1
            if redirects > MAX_REDIRECTS:
                raise UnsafeURL("Too many redirects")

            current_url = urljoin(current_url, location)
    finally:
        session.close()
