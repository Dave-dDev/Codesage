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
