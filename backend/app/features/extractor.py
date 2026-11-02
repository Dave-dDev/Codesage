from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..capture.reader import PacketRecord


FEATURE_LABELS: dict[str, str] = {
    "packet_count": "Packet count",
    "byte_count": "Byte volume",
    "flow_count": "Flow count",
    "unique_dst_ips": "Unique destinations",
    "unique_dst_ports": "Unique destination ports",
    "syn_count": "SYN packets",
    "ack_count": "ACK packets",
    "rst_count": "RST packets",
    "syn_ack_ratio": "SYN / ACK ratio",
    "dns_query_count": "DNS queries",
    "tcp_ratio": "TCP traffic share",
    "udp_ratio": "UDP traffic share",
    "mean_packet_size": "Mean packet size",
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
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    dns_query_count: int = 0
    tcp_count: int = 0
    udp_count: int = 0

    def add(self, packet: PacketRecord) -> None:
        self.packet_count += 1
        self.byte_count += packet.length
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
        self.syn_count += int(packet.syn)
        self.ack_count += int(packet.ack)
        self.rst_count += int(packet.rst)
        self.dns_query_count += int(packet.dns_query)
        self.tcp_count += int(packet.protocol == "TCP")
        self.udp_count += int(packet.protocol == "UDP")


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
        features = {
            "packet_count": float(packet_count),
            "byte_count": float(acc.byte_count),
            "flow_count": float(len(acc.flow_keys)),
            "unique_dst_ips": float(len(acc.dst_ips)),
            "unique_dst_ports": float(len(acc.dst_ports)),
            "syn_count": float(acc.syn_count),
            "ack_count": float(acc.ack_count),
            "rst_count": float(acc.rst_count),
            "syn_ack_ratio": float(acc.syn_count / (acc.ack_count + 1)),
            "dns_query_count": float(acc.dns_query_count),
            "tcp_ratio": float(tcp_ratio),
            "udp_ratio": float(udp_ratio),
            "mean_packet_size": float(acc.byte_count / packet_count),
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

