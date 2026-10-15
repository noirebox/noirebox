"""NB-04 — the egress rules: IPv4-mapped IPv6 unwrapped before the range
checks, private/reserved ranges refused for non-loopback hosts, webhook
targets held to the same bar. Pure resolution-level tests: no network,
no openssl — getaddrinfo is faked."""
import ipaddress
import socket

import pytest

from noirebox.anchors import _as_v4, _checked_endpoint, _resolve_pinned
from noirebox.cli import _webhook_url_ok


def _addrinfo(ip_str: str):
    family = socket.AF_INET6 if ":" in ip_str else socket.AF_INET
    return [(family, None, None, "", (ip_str, 0))]


def test_mapped_metadata_address_is_unwrapped():
    """The NB-04 bypass shape, deterministically handled on every Python:
    ::ffff:169.254.169.254 as a v6 object did NOT report link-local before
    3.13 (the range checks looked in fe80::/10) — python:3.12-slim, the
    shipped image, still behaves that way. The unwrap exposes the mapped
    v4 whatever the interpreter's era."""
    mapped = ipaddress.ip_address("::ffff:169.254.169.254")
    assert str(_as_v4(mapped)) == "169.254.169.254"
    assert _as_v4(ipaddress.ip_address("169.254.169.254")) == \
        ipaddress.ip_address("169.254.169.254")  # plain v4 passes through


def test_mapped_link_local_is_refused(monkeypatch):
    monkeypatch.setenv("NOIREBOX_TSA_ALLOWED_HOSTS", "tsa.example")
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda host, port: _addrinfo("::ffff:169.254.169.254"))
    with pytest.raises(RuntimeError, match="non-routable or link-local"):
        _checked_endpoint("http://tsa.example/tsa")


def test_external_host_resolving_to_private_range_is_refused(monkeypatch):
    """An allowlisted EXTERNAL hostname must resolve to a global address —
    10/8 inside is the SSRF pivot, allowed by nobody."""
    monkeypatch.setenv("NOIREBOX_TSA_ALLOWED_HOSTS", "tsa.example")
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda host, port: _addrinfo("10.0.0.42"))
    with pytest.raises(RuntimeError, match="non-routable or link-local"):
        _checked_endpoint("http://tsa.example/tsa")


def test_mapped_private_v6_refused_at_the_pinned_resolution(monkeypatch):
    """The transport half resolves once more — the same rule applies there,
    on the mapped v4 the v6 object hides."""
    monkeypatch.setenv("NOIREBOX_TSA_ALLOWED_HOSTS", "tsa.example")
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda host, port: _addrinfo("::ffff:172.16.5.5"))
    with pytest.raises(RuntimeError, match="non-routable or link-local"):
        _resolve_pinned("tsa.example", 443)


def test_loopback_default_host_still_allowed(monkeypatch):
    """The `make tsa` path is untouched: 127.0.0.1 in the default set only
    has to stay off link-local."""
    monkeypatch.delenv("NOIREBOX_TSA_ALLOWED_HOSTS", raising=False)
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda host, port: _addrinfo("127.0.0.1"))
    url = "http://127.0.0.1:3318/tsa"
    assert _checked_endpoint(url) == url
    assert _resolve_pinned("127.0.0.1", 3318) == "127.0.0.1"


# --- the alarm webhook, same bar (NB-04) --------------------------------------

def test_webhook_private_target_needs_opt_in(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda host, port: _addrinfo("192.168.1.10"))
    with pytest.raises(ValueError, match="NOIREBOX_WEBHOOK_ALLOW_PRIVATE"):
        _webhook_url_ok("http://hooks.internal.example/alarm")
    monkeypatch.setenv("NOIREBOX_WEBHOOK_ALLOW_PRIVATE", "1")
    assert _webhook_url_ok("http://hooks.internal.example/alarm") is None


def test_webhook_loopback_allowed_and_scheme_still_checked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda host, port: _addrinfo("127.0.0.1"))
    assert _webhook_url_ok("http://127.0.0.1:9999/alarm") is None
    with pytest.raises(ValueError, match="plain http\\(s\\)"):
        _webhook_url_ok("ftp://hooks.example/alarm")
