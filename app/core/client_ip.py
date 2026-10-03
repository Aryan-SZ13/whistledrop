import ipaddress
import logging
from typing import List, Union
from fastapi import Request

from app.core.config import settings

logger = logging.getLogger(__name__)

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def parse_trusted_cidrs(raw_cidrs: str) -> List[IPNetwork]:
    """Parse comma-separated CIDR networks into ipaddress network objects."""
    if not raw_cidrs or not raw_cidrs.strip():
        return []
    networks: List[IPNetwork] = []
    for item in raw_cidrs.split(","):
        cidr_str = item.strip()
        if not cidr_str:
            continue
        try:
            # strict=False allows host bits to be set, e.g., 192.168.1.1/24 -> 192.168.1.0/24
            networks.append(ipaddress.ip_network(cidr_str, strict=False))
        except ValueError:
            logger.warning("Invalid trusted proxy CIDR configured: %s", cidr_str)
    return networks


def canonicalize_ip(raw: str) -> str:
    """Normalize an IP string to its canonical form using Python's ipaddress module.

    - IPv4: strips leading zeros and normalizes representation (e.g., '010.0.0.1' -> '10.0.0.1')
    - IPv6: compresses to standard RFC 5952 representation
    - Unparseable strings: returned stripped as fallback (will still be securely HMAC-hashed)
    """
    if not raw:
        return "127.0.0.1"
    cleaned = raw.strip()

    # Pre-process IPv4 octets with leading zeros (e.g., "010.000.001.001" -> "10.0.1.1")
    parts = cleaned.split(".")
    if len(parts) == 4 and all(p.isdigit() and len(p) > 0 for p in parts):
        try:
            if all(0 <= int(p) <= 255 for p in parts):
                cleaned = ".".join(str(int(p)) for p in parts)
        except ValueError:
            pass

    try:
        addr = ipaddress.ip_address(cleaned)
        return str(addr)
    except ValueError:
        return raw.strip()



def is_trusted_peer(peer_ip: str, trusted_networks: List[IPNetwork]) -> bool:
    """Check if the socket peer belongs to any configured trusted proxy CIDR network."""
    if not trusted_networks or not peer_ip:
        return False
    try:
        addr = ipaddress.ip_address(peer_ip.strip())
        return any(addr in net for net in trusted_networks)
    except ValueError:
        return False


def resolve_client_ip(request: Request) -> str:
    """Determine the canonical client IP for rate-limit bucketing.

    Security model:
    - Socket peer address (`request.client.host`) is the root of trust.
    - Forwarded headers (`X-Forwarded-For`) are untrusted by default.
    - If `TRUSTED_PROXY_COUNT == 0` or `TRUSTED_PROXY_CIDRS` is empty:
      returns canonicalized socket peer address (forwarded headers completely ignored).
    - If socket peer does NOT belong to `TRUSTED_PROXY_CIDRS`:
      returns canonicalized socket peer address (forwarded headers completely ignored).
    - Only when the immediate socket peer is a verified trusted proxy:
      inspects `X-Forwarded-For` using right-to-left indexing minus `TRUSTED_PROXY_COUNT` hops.
    - All addresses are canonicalized through Python `ipaddress`.
    """
    peer = request.client.host if request.client else "127.0.0.1"
    canonical_peer = canonicalize_ip(peer)

    # 1. Default safe direct-connection mode
    if settings.TRUSTED_PROXY_COUNT <= 0 or not settings.TRUSTED_PROXY_CIDRS.strip():
        return canonical_peer

    # 2. Verify socket peer belongs to a trusted proxy network
    trusted_nets = parse_trusted_cidrs(settings.TRUSTED_PROXY_CIDRS)
    if not is_trusted_peer(peer, trusted_nets):
        return canonical_peer

    # 3. Peer is trusted — inspect X-Forwarded-For header
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if not forwarded_for:
        return canonical_peer

    parts = [p.strip() for p in forwarded_for.split(",") if p.strip()]
    client_index = len(parts) - 1 - settings.TRUSTED_PROXY_COUNT
    if client_index < 0:
        return canonical_peer

    return canonicalize_ip(parts[client_index])
