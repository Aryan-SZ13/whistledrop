import ipaddress
import logging
import socket
from typing import List, Tuple
from urllib.parse import urlsplit

from app.core.config import settings

logger = logging.getLogger(__name__)

DISALLOWED_NETWORKS = [
    # IPv4
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("100::/64"),
    ipaddress.ip_network("::ffff:0:0/96"),
]


def is_ip_disallowed(ip_str: str) -> bool:
    """Checks whether an IP address belongs to any disallowed/private/loopback/link-local network."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True

    # If IPv4-mapped IPv6 (::ffff:x.x.x.x), unwrap and test IPv4
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return True

    for net in DISALLOWED_NETWORKS:
        try:
            if ip in net:
                return True
        except TypeError:
            continue
    return False


def validate_webhook_url(raw_url: str) -> Tuple[str, str, int]:
    """Validates webhook URL syntax, scheme, credentials, and port."""
    parsed = urlsplit(raw_url.strip())
    scheme = parsed.scheme.lower()

    if settings.ALLOW_HTTP_WEBHOOKS:
        if scheme not in ("https", "http"):
            raise ValueError(f"Disallowed webhook scheme: {scheme}. Must be https (or http in dev).")
    else:
        if scheme != "https":
            raise ValueError(f"Webhook URL must use HTTPS scheme. Got: {scheme}")

    if parsed.username or parsed.password:
        raise ValueError("Webhook URLs must not contain embedded userinfo or credentials.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Webhook URL has an invalid or missing hostname.")

    port = parsed.port or (443 if scheme == "https" else 80)
    if not settings.ALLOW_HTTP_WEBHOOKS and port != 443:
        raise ValueError(f"Disallowed webhook destination port: {port}. Standard port 443 is required.")

    return scheme, hostname, port


def resolve_and_validate_destination(raw_url: str) -> List[str]:
    """Resolves target hostname to IPs and asserts all resolved IPs are public and routable."""
    _, hostname, port = validate_webhook_url(raw_url)

    # 1. If hostname is directly an IP address
    try:
        ip = ipaddress.ip_address(hostname)
        if is_ip_disallowed(str(ip)):
            raise ValueError(f"Disallowed destination IP address: {hostname}")
        return [str(ip)]
    except ValueError as e:
        # Not an IP string, proceed to DNS resolution
        pass

    # 2. DNS resolution
    try:
        addr_info = socket.getaddrinfo(hostname, port, family=socket.AF_UNSPEC, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise ValueError(f"Failed to resolve webhook destination hostname '{hostname}': {e}")

    valid_ips: List[str] = []
    for entry in addr_info:
        ip_str = entry[4][0]
        if is_ip_disallowed(ip_str):
            raise ValueError(f"Webhook destination '{hostname}' resolved to disallowed network address: {ip_str}")
        valid_ips.append(ip_str)

    if not valid_ips:
        raise ValueError(f"No valid routable IP addresses resolved for hostname '{hostname}'")

    return valid_ips
