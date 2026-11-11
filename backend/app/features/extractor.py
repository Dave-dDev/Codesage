from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..capture.reader import PacketRecord


import math
from collections import Counter

FEATURE_LABELS: dict[str, str] = {
    "packet_count": "Packet count",
    "byte_count": "Byte volume",
    "flow_count": "Flow count",
    "unique_dst_ips": "Unique destinations",
    "unique_dst_ports": "Unique destination ports",
    "syn_count": "SYN packets",
    "ack_count": "ACK packets",
    "rst_count": "RST packets",
    "fin_count": "FIN packets",
    "syn_ack_ratio": "SYN / ACK ratio",
    "dns_query_count": "DNS queries",
    "icmp_count": "ICMP packets",
    "tcp_ratio": "TCP traffic share",
    "udp_ratio": "UDP traffic share",
    "icmp_packet_ratio": "ICMP / packet ratio",
    "rst_packet_ratio": "RST / packet ratio",
    "mean_packet_size": "Mean packet size",
    "packet_size_variance": "Packet size variance",
    "dst_port_entropy": "Destination port entropy",
    "bytes_per_flow": "Bytes per flow",
    "packets_per_second": "Packets per second",
    "syn_packet_ratio": "SYN / packet ratio",
    "dns_packet_ratio": "DNS / packet ratio",
    "ports_per_destination": "Ports per destination",
    "ack_syn_ratio": "Completed handshake ratio",
}

FEATURE_NAMES: list[str] = list(FEATURE_LABELS)


@dataclass(slots=True)
class FeatureWindow:
    source_ip: str
    window_start: datetime
    window_end: datetime
    features: dict[str, float]
    packet_count: int
    byte_count: int
    flow_count: int

    def vector(self, feature_names: list[str] | None = None) -> list[float]:
        names = feature_names or FEATURE_NAMES
        return [float(self.features.get(name, 0.0)) for name in names]


@dataclass(slots=True)
class _WindowAccumulator:
    source_ip: str
    window_start: float
    packet_count: int = 0
    byte_count: int = 0
    flow_keys: set[tuple] = field(default_factory=set)
    dst_ips: set[str] = field(default_factory=set)
    dst_ports: set[int] = field(default_factory=set)
    dst_port_counts: Counter = field(default_factory=Counter)
    packet_lengths: list[int] = field(default_factory=list)
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    dns_query_count: int = 0
    tcp_count: int = 0
    udp_count: int = 0
    icmp_count: int = 0

    def add(self, packet: PacketRecord) -> None:
        self.packet_count += 1
        self.byte_count += packet.length
        self.packet_lengths.append(packet.length)
        self.flow_keys.add(
            (
                packet.src_ip,
                packet.src_port,
                packet.dst_ip,
                packet.dst_port,
                packet.protocol_number,
            )
        )
        self.dst_ips.add(packet.dst_ip)
        if packet.dst_port:
            self.dst_ports.add(packet.dst_port)
            self.dst_port_counts[packet.dst_port] += 1
        self.syn_count += int(packet.syn)
        self.ack_count += int(packet.ack)
        self.rst_count += int(packet.rst)
        self.fin_count += int(packet.fin)
        self.dns_query_count += int(packet.dns_query)
        self.tcp_count += int(packet.protocol == "TCP")
        self.udp_count += int(packet.protocol == "UDP")
        self.icmp_count += int(packet.protocol == "ICMP")


class WindowFeatureExtractor:
    """Aggregates packet metadata into per-source, fixed-time windows."""

    def __init__(self, window_seconds: int = 5, min_packets: int = 1) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window_seconds = window_seconds
        self.min_packets = max(1, min_packets)

    def extract(self, packets: list[PacketRecord]) -> list[FeatureWindow]:
        accumulators: dict[tuple[str, int], _WindowAccumulator] = {}

        for packet in packets:
            bucket = int(packet.timestamp // self.window_seconds) * self.window_seconds
            key = (packet.src_ip, bucket)
            accumulator = accumulators.get(key)
            if accumulator is None:
                accumulator = _WindowAccumulator(packet.src_ip, float(bucket))
                accumulators[key] = accumulator
            accumulator.add(packet)

        windows = [
            self._finalize(item)
            for item in accumulators.values()
            if item.packet_count >= self.min_packets
        ]
        windows.sort(key=lambda item: (item.window_start, item.source_ip))
        return windows

    def _finalize(self, acc: _WindowAccumulator) -> FeatureWindow:
        packet_count = acc.packet_count
        flow_count = max(len(acc.flow_keys), 1)
        tcp_ratio = acc.tcp_count / packet_count
        udp_ratio = acc.udp_count / packet_count
        icmp_packet_ratio = acc.icmp_count / packet_count
        rst_packet_ratio = acc.rst_count / packet_count

        mean_packet_size = float(acc.byte_count / packet_count)
        if len(acc.packet_lengths) > 1:
            variance = sum((x - mean_packet_size) ** 2 for x in acc.packet_lengths) / (len(acc.packet_lengths) - 1)
        else:
            variance = 0.0

        total_port_packets = sum(acc.dst_port_counts.values())
        if total_port_packets > 0:
            entropy = -sum(
                (count / total_port_packets) * math.log2(count / total_port_packets)
                for count in acc.dst_port_counts.values()
            )
        else:
            entropy = 0.0

        features = {
            "packet_count": float(packet_count),
            "byte_count": float(acc.byte_count),
            "flow_count": float(len(acc.flow_keys)),
            "unique_dst_ips": float(len(acc.dst_ips)),
            "unique_dst_ports": float(len(acc.dst_ports)),
            "syn_count": float(acc.syn_count),
            "ack_count": float(acc.ack_count),
            "rst_count": float(acc.rst_count),
            "fin_count": float(acc.fin_count),
            "syn_ack_ratio": float(acc.syn_count / (acc.ack_count + 1)),
            "dns_query_count": float(acc.dns_query_count),
            "icmp_count": float(acc.icmp_count),
            "tcp_ratio": float(tcp_ratio),
            "udp_ratio": float(udp_ratio),
            "icmp_packet_ratio": float(icmp_packet_ratio),
            "rst_packet_ratio": float(rst_packet_ratio),
            "mean_packet_size": mean_packet_size,
            "packet_size_variance": float(variance),
            "dst_port_entropy": float(entropy),
            "bytes_per_flow": float(acc.byte_count / flow_count),
            "packets_per_second": float(packet_count / self.window_seconds),
            "syn_packet_ratio": float(acc.syn_count / packet_count),
            "dns_packet_ratio": float(acc.dns_query_count / packet_count),
            "ports_per_destination": float(len(acc.dst_ports) / max(len(acc.dst_ips), 1)),
            "ack_syn_ratio": float(acc.ack_count / (acc.syn_count + 1)),
        }
        start = datetime.fromtimestamp(acc.window_start, tz=timezone.utc)
        end = datetime.fromtimestamp(
            acc.window_start + self.window_seconds, tz=timezone.utc
        )
        return FeatureWindow(
            source_ip=acc.source_ip,
            window_start=start,
            window_end=end,
            features=features,
            packet_count=packet_count,
            byte_count=acc.byte_count,
            flow_count=len(acc.flow_keys),
        )

