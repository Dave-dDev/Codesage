from app.features.extractor import FEATURE_NAMES, WindowFeatureExtractor
from app.capture.reader import PacketRecord
from datetime import datetime


def make_packet(ts: float, src: str = "10.0.0.1", dst: str = "10.0.0.2") -> PacketRecord:
    return PacketRecord(
        timestamp=ts,
        src_ip=src,
        dst_ip=dst,
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        protocol_number=6,
        length=100,
        syn=True,
    )


def test_same_source_is_grouped_into_fixed_windows() -> None:
    packets = [make_packet(1.1), make_packet(2.2), make_packet(6.1)]
    windows = WindowFeatureExtractor(window_seconds=5).extract(packets)
    assert len(windows) == 2
    assert windows[0].packet_count == 2
    assert windows[1].packet_count == 1
    assert set(windows[0].features) == set(FEATURE_NAMES)


def test_new_features_extracted_properly() -> None:
    # Test ICMP, RST, FIN, dst port entropy, packet size variance
    packets = [
        PacketRecord(
            timestamp=1.0,
            src_ip="10.0.0.99",
            dst_ip="10.0.0.1",
            src_port=0,
            dst_port=0,
            protocol="ICMP",
            protocol_number=1,
            length=64,
        ),
        PacketRecord(
            timestamp=2.0,
            src_ip="10.0.0.99",
            dst_ip="10.0.0.1",
            src_port=0,
            dst_port=0,
            protocol="ICMP",
            protocol_number=1,
            length=128,
        ),
        PacketRecord(
            timestamp=3.0,
            src_ip="10.0.0.99",
            dst_ip="10.0.0.1",
            src_port=50000,
            dst_port=80,
            protocol="TCP",
            protocol_number=6,
            length=60,
            rst=True,
            fin=True,
        ),
    ]
    windows = WindowFeatureExtractor(window_seconds=5).extract(packets)
    assert len(windows) == 1
    w = windows[0]
    features = w.features
    assert features["icmp_count"] == 2.0
    assert features["icmp_packet_ratio"] == 2.0 / 3.0
    assert features["rst_count"] == 1.0
    assert features["rst_packet_ratio"] == 1.0 / 3.0
    assert features["fin_count"] == 1.0
    assert features["packet_size_variance"] > 0.0
    assert features["dst_port_entropy"] == 0.0  # only one port used
