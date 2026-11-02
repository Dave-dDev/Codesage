from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scapy.all import DNS, ICMP, IP, TCP, UDP, PcapReader


TCP_SYN = 0x02
TCP_ACK = 0x10
TCP_RST = 0x04
TCP_FIN = 0x01


@dataclass(slots=True)
class PacketRecord:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    protocol_number: int
    length: int
    syn: bool = False
    ack: bool = False
    rst: bool = False
    fin: bool = False
    dns_query: bool = False


def _parse_packet(packet: Any, fallback_time: float) -> PacketRecord | None:
    if not packet.haslayer(IP):
        return None

    ip = packet[IP]
    timestamp = float(getattr(packet, "time", fallback_time))
    src_port = 0
    dst_port = 0
    protocol = "OTHER"
    protocol_number = int(ip.proto)
    syn = ack = rst = fin = False

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        protocol = "TCP"
        flags = int(tcp.flags)
        syn = bool(flags & TCP_SYN)
        ack = bool(flags & TCP_ACK)
        rst = bool(flags & TCP_RST)
        fin = bool(flags & TCP_FIN)
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
        protocol = "UDP"
    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    dns_query = False
    if packet.haslayer(DNS):
        dns = packet[DNS]
        try:
            dns_query = int(dns.qr) == 0 and int(dns.qdcount) > 0
        except (AttributeError, TypeError, ValueError):
            dns_query = False

    return PacketRecord(
        timestamp=timestamp,
        src_ip=str(ip.src),
        dst_ip=str(ip.dst),
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        protocol_number=protocol_number,
        length=len(packet),
        syn=syn,
        ack=ack,
        rst=rst,
        fin=fin,
        dns_query=dns_query,
    )


def read_pcap(path: Path | str) -> list[PacketRecord]:
    records: list[PacketRecord] = []
    with PcapReader(str(path)) as reader:
        for packet in reader:
            record = _parse_packet(packet, float(getattr(packet, "time", 0.0)))
            if record is not None:
                records.append(record)
    records.sort(key=lambda item: item.timestamp)
    return records


def read_pcap_iter(path: Path | str):
    """Yield packet metadata without loading the entire capture in memory."""
    with PcapReader(str(path)) as reader:
        for packet in reader:
            record = _parse_packet(packet, float(getattr(packet, "time", 0.0)))
            if record is not None:
                yield record
