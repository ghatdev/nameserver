"""Curated parking / cleanup / sinkhole CIDR ranges.

A response IP landing in one of these ranges is a STRONG signal that the
domain is no longer serving its original content — either because a
registrar has reclaimed it, a hosting provider has parked it, or a
takedown has sunkholed it. For training-data hygiene, a flow whose
response IPs all fall in here is likely not representative of active
malicious behavior (even if the domain is currently on Hagezi TIF) and
should be down-weighted or excluded.

THIS LIST IS NOT EXHAUSTIVE. CIDR ranges drift over time — registrar
parking IPs get reassigned, sinkhole projects publish new ranges, and
cleanup IPs for major hosters aren't publicly enumerated. We start with
the most widely-documented ranges and expect this file to grow. When
adding an entry, include a citation in the comment so future maintainers
can verify it's still parking.

Applied by `ml/confidence_active.py` — see that module for the scoring
semantics and the full design motivation (project_resolution_injector.md).
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Network, ip_address, ip_network
from typing import Final


@dataclass(frozen=True)
class ParkingRange:
    cidr: str
    category: str  # "registrar_parking" | "hosting_cleanup" | "sinkhole"
    owner: str
    note: str


# Curated list — conservative. Expand over time with cited sources.
PARKING_RANGES: Final[list[ParkingRange]] = [
    # GoDaddy parking cluster. 76.223.0.0/16 + 184.168.0.0/14 are the
    # historical "coming soon" landing IPs; widely documented in
    # public passive-DNS analyses and abuse reports.
    ParkingRange(
        cidr="76.223.0.0/16",
        category="registrar_parking",
        owner="godaddy",
        note="GoDaddy parking cluster — coming-soon landing",
    ),
    ParkingRange(
        cidr="184.168.0.0/14",
        category="registrar_parking",
        owner="godaddy",
        note="GoDaddy/Wild West Domains hosting used for parking",
    ),
    # Namecheap parking. Tied to their "parkingcrew"/afternic integration.
    ParkingRange(
        cidr="199.59.243.0/24",
        category="registrar_parking",
        owner="namecheap",
        note="Namecheap parking — landing pages",
    ),
    # Sedo (domain brokerage / sale landing pages).
    ParkingRange(
        cidr="64.190.62.0/24",
        category="registrar_parking",
        owner="sedo",
        note="Sedo parking — for-sale landing",
    ),
    # ShadowServer — publicly documented sinkhole ranges. See:
    # https://www.shadowserver.org/what-we-do/sinkhole/
    ParkingRange(
        cidr="184.105.64.0/20",
        category="sinkhole",
        owner="shadowserver",
        note="ShadowServer sinkhole block (publicly documented)",
    ),
    # Common takedown "blackhole" — AS15169 / 0.0.0.0 is sometimes
    # observed but we leave those to the rcode=NOERROR-with-0-IPs rule.
]

def _compile_networks() -> tuple[
    list[tuple[IPv4Network, ParkingRange]],
    list[tuple[IPv6Network, ParkingRange]],
]:
    v4: list[tuple[IPv4Network, ParkingRange]] = []
    v6: list[tuple[IPv6Network, ParkingRange]] = []
    for entry in PARKING_RANGES:
        try:
            net = ip_network(entry.cidr, strict=False)
        except ValueError:
            continue
        if isinstance(net, IPv4Network):
            v4.append((net, entry))
        elif isinstance(net, IPv6Network):
            v6.append((net, entry))
    return v4, v6


_V4_NETS: Final[list[tuple[IPv4Network, ParkingRange]]]
_V6_NETS: Final[list[tuple[IPv6Network, ParkingRange]]]
_V4_NETS, _V6_NETS = _compile_networks()


def ip_in_parking(ip_str: str) -> bool:
    """True if `ip_str` falls within any curated parking/sinkhole range."""
    if not ip_str:
        return False
    try:
        ip = ip_address(ip_str)
    except ValueError:
        return False
    if isinstance(ip, IPv4Address):
        return any(ip in net for net, _ in _V4_NETS)
    return any(ip in net for net, _ in _V6_NETS)


def categorize_ip(ip_str: str) -> ParkingRange | None:
    """Return the matching ParkingRange entry for auditing / labeling."""
    if not ip_str:
        return None
    try:
        ip = ip_address(ip_str)
    except ValueError:
        return None
    if isinstance(ip, IPv4Address):
        for net, entry in _V4_NETS:
            if ip in net:
                return entry
    else:
        for net, entry in _V6_NETS:
            if ip in net:
                return entry
    return None
