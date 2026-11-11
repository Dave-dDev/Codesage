from __future__ import annotations

import json
import time
from dataclasses import asdict

from sqlalchemy.orm import Session

from .config import settings
from .db import SessionLocal
from .features.extractor import FeatureWindow
from .ml.detector import AnomalyDetector, DetectionResult
from .models import Alert, FlowWindow
from .timeutils import iso_utc
from .ws import ConnectionManager


class DetectionEngine:
    def __init__(self, detector: AnomalyDetector, broadcaster: ConnectionManager) -> None:
        self.detector = detector
        self.broadcaster = broadcaster
        self._last_alert_at: dict[str, float] = {}

    def reset_state(self) -> None:
        self._last_alert_at.clear()

    async def ingest(self, window: FeatureWindow) -> Alert | None:
        result = self.detector.score(window)
        db: Session = SessionLocal()
        alert_payload: dict | None = None
        try:
            flow = FlowWindow(
                source_ip=window.source_ip,
                window_start=window.window_start,
                window_end=window.window_end,
                packet_count=window.packet_count,
                byte_count=window.byte_count,
                flow_count=window.flow_count,
                score=result.score,
                is_anomaly=result.is_anomaly,
                features_json=json.dumps(window.features, sort_keys=True),
            )
            db.add(flow)
            db.flush()

            alert = None
            now = time.monotonic()
            last_alert = self._last_alert_at.get(window.source_ip, 0.0)
            cooldown_elapsed = now - last_alert >= settings.alert_cooldown_seconds
            if result.is_anomaly and cooldown_elapsed:
                self._last_alert_at[window.source_ip] = now
                alert = Alert(
                    flow_window_id=flow.id,
                    source_ip=window.source_ip,
                    severity=self._severity(result.score),
                    score=result.score,
                    title=self._alert_title(result, window),
                    reasons_json=json.dumps(
                        [asdict(explanation) for explanation in result.explanations]
                    ),
                )
                db.add(alert)
                db.flush()
                alert_payload = self._serialize_alert(alert, flow)

            db.commit()
            db.refresh(flow)
        finally:
            db.close()

        await self.broadcaster.broadcast(
            "window",
            {
                "source_ip": window.source_ip,
                "window_start": window.window_start.isoformat(),
                "score": result.score,
                "is_anomaly": result.is_anomaly,
                "packet_count": window.packet_count,
                "byte_count": window.byte_count,
                "flow_count": window.flow_count,
            },
        )
        if alert_payload is not None:
            await self.broadcaster.broadcast("alert", alert_payload)
        return alert

    @staticmethod
    def _severity(score: float) -> str:
        if score >= 88:
            return "critical"
        if score >= 75:
            return "high"
        if score >= 60:
            return "medium"
        return "low"

    @staticmethod
    def _alert_title(result: DetectionResult, window: FeatureWindow) -> str:
        features = window.features
        if features.get("icmp_packet_ratio", 0) >= 0.6 or features.get("icmp_count", 0) >= 30:
            return "ICMP flood pattern detected"
        if features.get("rst_packet_ratio", 0) >= 0.5 or features.get("rst_count", 0) >= 30:
            return "TCP RST storm detected"
        if (
            features.get("fin_count", 0) >= 15
            and features.get("syn_count", 0) >= 15
            and features.get("ack_count", 0) <= 5
        ):
            return "Connection exhaustion attempt detected"
        if features.get("dns_packet_ratio", 0) >= 0.5 and features.get("dns_query_count", 0) >= 20:
            return "DNS query burst detected"
        if features.get("syn_packet_ratio", 0) >= 0.75 and features.get("syn_count", 0) >= 100:
            return "SYN-flood pattern detected"
        if (
            features.get("ports_per_destination", 0) >= 10
            and features.get("unique_dst_ports", 0) >= 20
        ) or features.get("dst_port_entropy", 0) >= 3.5:
            return "Port-scan pattern detected"
        if features.get("packet_count", 0) >= 500 or features.get("packets_per_second", 0) >= 100:
            return "Traffic volume spike detected"
        names = [item.name for item in result.explanations]
        if "unique_dst_ports" in names or "dst_port_entropy" in names:
            return "Port-scan pattern detected"
        if "icmp_count" in names or "icmp_packet_ratio" in names:
            return "ICMP flood pattern detected"
        if "rst_count" in names or "rst_packet_ratio" in names:
            return "TCP RST storm detected"
        return "Anomalous traffic pattern detected"

    @staticmethod
    def _serialize_alert(alert: Alert, flow: FlowWindow) -> dict:
        return {
            "id": alert.id,
            "flow_window_id": flow.id,
            "source_ip": alert.source_ip,
            "severity": alert.severity,
            "score": alert.score,
            "title": alert.title,
            "reasons": json.loads(alert.reasons_json),
            "status": alert.status,
            "created_at": iso_utc(alert.created_at),
            "updated_at": iso_utc(alert.updated_at),
        }

