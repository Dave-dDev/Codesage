from __future__ import annotations

import math
import random
import time
from pathlib import Path

from scapy.all import DNS, DNSQR, Ether, ICMP, IP, TCP, UDP, wrpcap

from ..config import settings


CLIENTS = [f"10.0.0.{index}" for index in range(11, 23)]
SERVERS = ["10.0.0.100", "10.0.0.101", "10.0.0.102"]
DNS_SERVER = "10.0.0.53"


def _tcp_packet(
    timestamp: float,
    src: str,
    dst: str,
    sport: int,
    dport: int,
    flags: str,
    payload_size: int = 0,
):
    packet = (
        Ether()
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags=flags)
    )
    if payload_size:
        packet = packet / (b"x" * payload_size)
    packet.time = timestamp
    return packet


def _icmp_packet(timestamp: float, src: str, dst: str, payload_size: int = 32):
    packet = (
        Ether()
        / IP(src=src, dst=dst)
        / ICMP(type=8, code=0)
    )
    if payload_size:
        packet = packet / (b"p" * payload_size)
    packet.time = timestamp
    return packet


def _dns_query(timestamp: float, src: str, qname: str):
    packet = (
        Ether()
        / IP(src=src, dst=DNS_SERVER)
        / UDP(sport=random.randint(49152, 65535), dport=53)
        / DNS(rd=1, qd=DNSQR(qname=qname))
    )
    packet.time = timestamp
    return packet


def _append_normal_traffic(
    packets: list,
    duration: int,
    base_time: float,
    seed: int,
    clients: list[str] | None = None,
) -> None:
    rng = random.Random(seed)
    active_clients = clients or CLIENTS

    for second in range(duration):
        load = 0.75 + 0.25 * math.sin((2 * math.pi * second) / 70)
        for client_index, client in enumerate(active_clients):
            requests = 1 if rng.random() < 0.72 * load else 2
            for request_index in range(requests):
                server = rng.choice(SERVERS)
                dport = rng.choice([443, 80, 8080])
                sport = rng.randint(49152, 65535)
                flow_id = rng.randint(1, 65535)
                offset = request_index * 0.35 + client_index * 0.015
                start = base_time + second + offset

                packets.append(
                    _tcp_packet(start, client, server, sport, dport, "S")
                )
                packets.append(
                    _tcp_packet(start + 0.018, server, client, dport, sport, "SA")
                )
                packets.append(
                    _tcp_packet(start + 0.035, client, server, sport, dport, "A")
                )
                packets.append(
                    _tcp_packet(
                        start + 0.055,
                        client,
                        server,
                        sport,
                        dport,
                        "PA",
                        payload_size=rng.randint(140, 900),
                    )
                )
                packets.append(
                    _tcp_packet(
                        start + 0.090,
                        server,
                        client,
                        dport,
                        sport,
                        "PA",
                        payload_size=rng.randint(400, 1400),
                    )
                )

            if second % 4 == client_index % 4:
                packets.append(
                    _dns_query(
                        base_time + second + 0.12,
                        client,
                        f"service-{rng.randint(1, 12)}.internal.example",
                    )
                )


def generate_normal_pcap(path: Path, duration: int = 300, seed: int = 7) -> Path:
    base_time = time.time() - duration
    packets: list = []
    _append_normal_traffic(packets, duration, base_time, seed)
    packets.sort(key=lambda packet: packet.time)
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), packets)
    return path


def generate_mixed_pcap(path: Path, duration: int = 160, seed: int = 19) -> Path:
    base_time = time.time() - duration
    packets: list = []
    _append_normal_traffic(packets, duration, base_time, seed)
    rng = random.Random(seed + 3)

    scanner = "10.0.0.66"
    # Port scan: 18 seconds of unique destination ports.
    for second in range(25, 43):
        for offset in range(8):
            packets.append(
                _tcp_packet(
                    base_time + second + offset * 0.11,
                    scanner,
                    "10.0.0.100",
                    rng.randint(40000, 65000),
                    1 + (second - 25) * 8 + offset,
                    "S",
                )
            )

    flooder = "10.0.0.77"
    # SYN flood: a sustained burst with almost no completed handshakes.
    for second in range(55, 64):
        for offset in range(55):
            packets.append(
                _tcp_packet(
                    base_time + second + offset * 0.016,
                    flooder,
                    "10.0.0.100",
                    rng.randint(40000, 65000),
                    443,
                    "S",
                )
            )

    dns_attacker = "10.0.0.88"
    # DNS burst: many short-lived UDP queries from one source.
    for second in range(78, 87):
        for offset in range(42):
            packets.append(
                _dns_query(
                    base_time + second + offset * 0.021,
                    dns_attacker,
                    f"burst-{second}-{offset}.example",
                )
            )

    icmp_flooder = "10.0.0.99"
    # ICMP ping flood: rapid echo requests to exhaust bandwidth / host.
    for second in range(95, 104):
        for offset in range(48):
            packets.append(
                _icmp_packet(
                    base_time + second + offset * 0.018,
                    icmp_flooder,
                    "10.0.0.101",
                    payload_size=64,
                )
            )

    rst_attacker = "10.0.0.55"
    # TCP RST storm: rapid unsolicited resets attempting to tear down connections.
    for second in range(112, 121):
        for offset in range(40):
            packets.append(
                _tcp_packet(
                    base_time + second + offset * 0.022,
                    rst_attacker,
                    "10.0.0.100",
                    rng.randint(40000, 65000),
                    80,
                    "R",
                )
            )

    exhaust_attacker = "10.0.0.44"
    # Connection exhaustion / slowloris: continuous SYN attempts with dangling FINs and zero full data flows.
    for second in range(128, 138):
        for offset in range(18):
            sport = 30000 + (second - 128) * 18 + offset
            packets.append(
                _tcp_packet(
                    base_time + second + offset * 0.05,
                    exhaust_attacker,
                    "10.0.0.102",
                    sport,
                    8080,
                    "S",
                )
            )
            packets.append(
                _tcp_packet(
                    base_time + second + offset * 0.05 + 0.02,
                    exhaust_attacker,
                    "10.0.0.102",
                    sport,
                    8080,
                    "F",
                )
            )

    packets.sort(key=lambda packet: packet.time)
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), packets)
    return path


def ensure_demo_data() -> None:
    if not settings.normal_pcap.exists():
        generate_normal_pcap(settings.normal_pcap, duration=300, seed=7)
    if not settings.mixed_pcap.exists():
        generate_mixed_pcap(settings.mixed_pcap, duration=120, seed=19)
