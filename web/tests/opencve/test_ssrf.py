import socket
from unittest import mock
from urllib.parse import urlparse

import pytest
import requests
from django.test import override_settings

from opencve.utils.ssrf import (
    MAX_REDIRECTS,
    UnsafeURL,
    _pin_dns,
    safe_request,
    validate_public_http_url,
)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1",
        "http://127.0.0.1:8080/path",
        "http://localhost",
        "http://localhost.",
        "http://LOCALHOST",
        "http://0",
        "http://0.0.0.0",
        "http://2130706433",
        "http://0x7f000001",
        "http://0177.0.0.1",
        "http://10.0.0.1",
        "http://172.16.0.1",
        "http://192.168.1.1",
        "http://169.254.169.254",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]",
        "http://[fe80::1]",
        "http://[fc00::1]",
        "http://[fd00::1]",
        "http://[::ffff:127.0.0.1]",
        "http://user:pass@example.com",
        "file:///etc/passwd",
        "gopher://example.com",
        "ftp://example.com",
    ],
)
def test_validate_public_http_url_rejects_unsafe_urls(url):
    """Reject loopback, private, link-local, metadata, credentials and bad schemes."""
    with pytest.raises(UnsafeURL):
        validate_public_http_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "https://example.com/path",
        "http://example.com:8080/path",
    ],
)
def test_validate_public_http_url_allows_public_urls(url):
    """Accept public HTTP/HTTPS URLs when DNS resolves to a public IP."""
    with mock.patch(
        "opencve.utils.ssrf._real_getaddrinfo",
        return_value=[
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("93.184.216.34", 443 if ":8080" not in url else 8080),
            )
        ],
    ):
        validate_public_http_url(url)


def test_validate_public_http_url_rejects_hostname_resolving_to_private_ip():
    """Reject a public hostname when DNS resolves to a private address."""
    with mock.patch(
        "opencve.utils.ssrf._real_getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 80)),
        ],
    ):
        with pytest.raises(UnsafeURL):
            validate_public_http_url("http://evil.example.com")


def test_validate_public_http_url_rejects_if_any_resolved_ip_is_private():
    """Reject when at least one resolved IP in a mixed DNS answer is private."""
    with mock.patch(
        "opencve.utils.ssrf._real_getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443)),
        ],
    ):
        with pytest.raises(UnsafeURL):
            validate_public_http_url("https://mixed.example.com")


@pytest.mark.parametrize(
    "url",
    [
        "http://10.1.2.3",
        "https://10.1.2.3:8443/path",
        "http://[::ffff:10.1.2.3]",
        "http://192.168.1.10",
        "http://[fd00::1]",
    ],
)
@override_settings(
    NOTIFICATION_ALLOWED_INTERNAL_NETWORKS=[
        "10.0.0.0/8",
        "192.168.1.10/32",
        "fd00::/8",
    ]
)
def test_validate_public_http_url_allows_configured_internal_networks(url):
    """Accept private addresses belonging to the configured networks."""
    validate_public_http_url(url)


@pytest.mark.parametrize(
    "url",
    [
        # Private addresses outside of the configured network
        "http://172.16.0.1",
        "http://192.168.1.11",
        "http://[fd00::1]",
        "http://[::ffff:172.16.0.1]",
        "http://127.0.0.1",
        # Other protections still apply to the configured network
        "http://localhost",
        "http://0x0a000001",
        "http://user:pass@10.1.2.3",
        "file://10.1.2.3/etc/passwd",
    ],
)
@override_settings(
    NOTIFICATION_ALLOWED_INTERNAL_NETWORKS=["10.0.0.0/8", "192.168.1.10/32"]
)
def test_validate_public_http_url_rejects_outside_internal_networks(url):
    """Keep rejecting URLs not covered by the configured networks."""
    with pytest.raises(UnsafeURL):
        validate_public_http_url(url)


@override_settings(NOTIFICATION_ALLOWED_INTERNAL_NETWORKS=["10.1.2.3/8"])
def test_validate_public_http_url_accepts_network_with_host_bits():
    """Accept a configured network written with its host bits set."""
    validate_public_http_url("http://10.200.0.1")


@override_settings(NOTIFICATION_ALLOWED_INTERNAL_NETWORKS=["10.0.0.0/8"])
def test_validate_public_http_url_allows_hostname_in_internal_network():
    """Accept a hostname when all its IPs are public or in the configured networks."""
    with mock.patch(
        "opencve.utils.ssrf._real_getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
        ],
    ):
        validate_public_http_url("https://n8n.int.example.org")


@override_settings(NOTIFICATION_ALLOWED_INTERNAL_NETWORKS=["10.0.0.0/8"])
def test_validate_public_http_url_rejects_hostname_outside_internal_networks():
    """Reject a hostname when one of its IPs is outside the configured networks."""
    with mock.patch(
        "opencve.utils.ssrf._real_getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.0.1", 443)),
        ],
    ):
        with pytest.raises(UnsafeURL):
            validate_public_http_url("https://n8n.int.example.org")


@override_settings(NOTIFICATION_ALLOWED_INTERNAL_NETWORKS=["169.254.0.0/16"])
def test_validate_public_http_url_never_allows_cloud_metadata():
    """Keep the metadata endpoint blocked when a configured network contains it."""
    validate_public_http_url("http://169.254.1.1")

    with pytest.raises(UnsafeURL):
        validate_public_http_url("http://169.254.169.254")

    with mock.patch(
        "opencve.utils.ssrf._real_getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80)),
        ],
    ):
        with pytest.raises(UnsafeURL):
            validate_public_http_url("http://metadata.example.com")

    with pytest.raises(UnsafeURL):
        validate_public_http_url("http://[::ffff:169.254.169.254]")


@override_settings(NOTIFICATION_ALLOWED_INTERNAL_NETWORKS=["10.0.0.0/8"])
@mock.patch("opencve.utils.ssrf.requests.Session")
def test_safe_request_revalidates_redirect_outside_internal_networks(mock_session):
    """Reject a redirect leaving the configured networks."""
    response = mock.Mock(status_code=302, headers={"Location": "http://192.168.0.1/"})
    mock_session.return_value.request.return_value = response

    with pytest.raises(UnsafeURL):
        safe_request("POST", "http://10.0.0.1/hook")

    assert mock_session.return_value.request.call_count == 1


def test_validate_public_http_url_rejects_missing_hostname():
    """Reject URLs without a hostname."""
    with pytest.raises(UnsafeURL, match="hostname"):
        validate_public_http_url("http://")


def test_validate_public_http_url_rejects_invalid_port():
    """Reject URLs with an out-of-range port number."""
    with pytest.raises(UnsafeURL, match="port"):
        validate_public_http_url("http://example.com:70000")


def _mock_response(status_code, headers=None, text=""):
    response = mock.Mock(spec=requests.Response)
    response.status_code = status_code
    response.headers = headers or {}
    response.text = text
    return response


@mock.patch("opencve.utils.ssrf._parse_and_validate_url")
@mock.patch("opencve.utils.ssrf.requests.Session")
def test_safe_request_returns_success_response(mock_session_cls, mock_parse):
    """Return the response and disable proxy env trust for valid public URLs."""
    parsed = urlparse("https://example.com/hook")
    mock_parse.return_value = (parsed, "example.com", 443, ["93.184.216.34"])
    session = mock_session_cls.return_value
    session.request.return_value = _mock_response(
        200,
        headers={"X-Test": "ok"},
        text='{"ok": true}',
    )

    response = safe_request("POST", "https://example.com/hook", json={"a": 1})

    assert response.status_code == 200
    assert response.text == '{"ok": true}'
    session.request.assert_called_once()
    assert session.trust_env is False
    mock_parse.assert_called_with("https://example.com/hook")
    session.close.assert_called_once()


@mock.patch("opencve.utils.ssrf._parse_and_validate_url")
@mock.patch("opencve.utils.ssrf.requests.Session")
def test_safe_request_rejects_redirect_to_localhost(mock_session_cls, mock_parse):
    """Reject redirects that target a private or loopback address."""
    parsed = urlparse("https://example.com/hook")
    mock_parse.side_effect = [
        (parsed, "example.com", 443, ["93.184.216.34"]),
        UnsafeURL("URL targets a private or reserved address"),
    ]
    session = mock_session_cls.return_value
    session.request.return_value = _mock_response(
        302,
        headers={"Location": "http://127.0.0.1/internal"},
    )

    with pytest.raises(UnsafeURL, match="private or reserved"):
        safe_request("POST", "https://example.com/hook", json={"a": 1})


@mock.patch("opencve.utils.ssrf._parse_and_validate_url")
@mock.patch("opencve.utils.ssrf.requests.Session")
def test_safe_request_follows_relative_redirect(mock_session_cls, mock_parse):
    """Follow a relative redirect after revalidating the joined destination URL."""
    first_parsed = urlparse("https://example.com/base")
    second_parsed = urlparse("https://example.com/next")
    mock_parse.side_effect = [
        (first_parsed, "example.com", 443, ["93.184.216.34"]),
        (second_parsed, "example.com", 443, ["93.184.216.34"]),
    ]
    session = mock_session_cls.return_value
    session.request.side_effect = [
        _mock_response(302, headers={"Location": "/next"}),
        _mock_response(200, headers={"X-Done": "1"}, text="done"),
    ]

    response = safe_request("POST", "https://example.com/base", json={"a": 1})

    assert response.status_code == 200
    assert response.text == "done"
    assert session.request.call_count == 2
    assert mock_parse.call_args_list[-1][0][0] == "https://example.com/next"


@mock.patch("opencve.utils.ssrf._parse_and_validate_url")
@mock.patch("opencve.utils.ssrf.requests.Session")
def test_safe_request_rejects_too_many_redirects(mock_session_cls, mock_parse):
    """Reject redirect chains longer than the configured maximum."""
    parsed = urlparse("https://example.com/start")
    mock_parse.return_value = (parsed, "example.com", 443, ["93.184.216.34"])
    session = mock_session_cls.return_value
    session.request.return_value = _mock_response(
        302,
        headers={"Location": "https://example.com/next"},
    )

    with pytest.raises(UnsafeURL, match="Too many redirects"):
        safe_request("POST", "https://example.com/start", json={"a": 1})

    assert session.request.call_count == MAX_REDIRECTS + 1


def test_pin_dns_returns_only_prevalidated_ips():
    """Prevent DNS rebinding by serving validated IPs during connect."""
    pinned_ip = "93.184.216.34"
    rebound_ip = "127.0.0.1"

    with mock.patch("opencve.utils.ssrf._real_getaddrinfo") as mock_real:
        mock_real.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (rebound_ip, 443)),
        ]
        with _pin_dns("example.com", 443, [pinned_ip]):
            results = socket.getaddrinfo(
                "example.com",
                443,
                type=socket.SOCK_STREAM,
            )

    assert results[0][4][0] == pinned_ip
    mock_real.assert_not_called()


def test_pin_dns_ignores_mismatched_port():
    """Serve pinned IPs for the hostname even when the caller uses another port."""
    pinned_ip = "93.184.216.34"

    with mock.patch("opencve.utils.ssrf._real_getaddrinfo") as mock_real:
        with _pin_dns("example.com", 443, [pinned_ip]):
            results = socket.getaddrinfo(
                "example.com",
                8080,
                type=socket.SOCK_STREAM,
            )

    assert results[0][4][0] == pinned_ip
    mock_real.assert_not_called()
