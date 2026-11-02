from __future__ import annotations

import json
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Alert, FlowWindow
from ..timeutils import ensure_utc
from ..schemas import (
    AlertDetail,
    AlertOut,
    AlertUpdate,
    DemoStart,
    DemoStatus,
    FeatureOut,
    FlowWindowOut,
    ModelInfoOut,
    SummaryOut,
    TimelinePoint,
)

router = APIRouter(prefix="/api")


def _alert_out(alert: Alert) -> AlertOut:
    return AlertOut(
        id=alert.id,
        flow_window_id=alert.flow_window_id,
        source_ip=alert.source_ip,
        severity=alert.severity,
        score=alert.score,
        title=alert.title,
        reasons=[FeatureOut(**item) for item in json.loads(alert.reasons_json)],
        status=alert.status,
        created_at=ensure_utc(alert.created_at),
        updated_at=ensure_utc(alert.updated_at),
    )


def _flow_out(flow: FlowWindow) -> FlowWindowOut:
    return FlowWindowOut(
        id=flow.id,
        source_ip=flow.source_ip,
        window_start=ensure_utc(flow.window_start),
        window_end=ensure_utc(flow.window_end),
        packet_count=flow.packet_count,
        byte_count=flow.byte_count,
        flow_count=flow.flow_count,
        score=flow.score,
        is_anomaly=flow.is_anomaly,
        features=json.loads(flow.features_json),
    )


@router.get("/health")
def health(request: Request) -> dict:
    return {"status": "ok", "service": "NetSentry AI", "demo": request.app.state.demo.status()}


@router.get("/summary", response_model=SummaryOut)
def summary(request: Request, db: Session = Depends(get_db)) -> SummaryOut:
    latest = db.scalar(select(func.max(FlowWindow.window_start)))
    total_windows = db.scalar(select(func.count(FlowWindow.id))) or 0
    anomaly_windows = db.scalar(
        select(func.count(FlowWindow.id)).where(FlowWindow.is_anomaly.is_(True))
    ) or 0
    alerts_last_15m = 0
    active_sources = 0
    packets_per_second = 0.0

    if latest is not None:
        recent_cutoff = latest - timedelta(seconds=30)
        alerts_cutoff = latest - timedelta(minutes=15)
        active_sources = db.scalar(
            select(func.count(func.distinct(FlowWindow.source_ip))).where(
                FlowWindow.window_start >= recent_cutoff
            )
        ) or 0
        recent_packets = db.scalar(
            select(func.sum(FlowWindow.packet_count)).where(
                FlowWindow.window_start >= recent_cutoff
            )
        ) or 0
        packets_per_second = round(float(recent_packets) / 30.0, 1)
        alerts_last_15m = db.scalar(
            select(func.count(Alert.id))
            .join(FlowWindow, Alert.flow_window_id == FlowWindow.id)
            .where(FlowWindow.window_start >= alerts_cutoff)
        ) or 0

    timeline_rows = db.execute(
        select(
            FlowWindow.window_start,
            func.max(FlowWindow.score).label("max_score"),
            func.sum(FlowWindow.packet_count).label("packets"),
            func.sum(FlowWindow.byte_count).label("bytes"),
            func.count(func.distinct(FlowWindow.source_ip)).label("sources"),
        )
        .group_by(FlowWindow.window_start)
        .order_by(desc(FlowWindow.window_start))
        .limit(50)
    ).all()
    timeline = [
        TimelinePoint(
            timestamp=ensure_utc(row.window_start),
            max_score=round(float(row.max_score), 2),
            packets=int(row.packets),
            bytes=int(row.bytes),
            sources=int(row.sources),
        )
        for row in reversed(timeline_rows)
    ]

    detector = request.app.state.detector
    return SummaryOut(
        packets_per_second=packets_per_second,
        active_sources=active_sources,
        total_windows=total_windows,
        alerts_last_15m=alerts_last_15m,
        alert_ratio=round(anomaly_windows / total_windows * 100, 1) if total_windows else 0.0,
        model_threshold=detector.threshold_score,
        demo_running=request.app.state.demo.running,
        demo_scenario=request.app.state.demo.scenario,
        timeline=timeline,
    )


@router.get("/flows", response_model=list[FlowWindowOut])
def flows(
    source_ip: str | None = None,
    min_score: float | None = None,
    limit: int = 100,
    db: Session = Depends(get_db),
) -> list[FlowWindowOut]:
    query = select(FlowWindow).order_by(desc(FlowWindow.window_start), desc(FlowWindow.id))
    if source_ip:
        query = query.where(FlowWindow.source_ip == source_ip)
    if min_score is not None:
        query = query.where(FlowWindow.score >= min_score)
    rows = db.scalars(query.limit(min(max(limit, 1), 500))).all()
    return [_flow_out(row) for row in rows]


@router.get("/alerts", response_model=list[AlertOut])
def alerts(
    status: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
) -> list[AlertOut]:
    query = select(Alert).order_by(desc(Alert.id))
    if status:
        query = query.where(Alert.status == status)
    rows = db.scalars(query.limit(min(max(limit, 1), 200))).all()
    return [_alert_out(row) for row in rows]


@router.get("/alerts/{alert_id}", response_model=AlertDetail)
def alert_detail(alert_id: int, db: Session = Depends(get_db)) -> AlertDetail:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    base = _alert_out(alert)
    return AlertDetail(**base.model_dump(), flow=_flow_out(alert.flow))


@router.patch("/alerts/{alert_id}", response_model=AlertOut)
def update_alert(
    alert_id: int, payload: AlertUpdate, db: Session = Depends(get_db)
) -> AlertOut:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = payload.status
    db.commit()
    db.refresh(alert)
    return _alert_out(alert)


@router.get("/model/info", response_model=ModelInfoOut)
def model_info(request: Request) -> ModelInfoOut:
    return ModelInfoOut(**request.app.state.detector.info)


@router.post("/demo/start", response_model=DemoStatus)
async def start_demo(payload: DemoStart, request: Request) -> DemoStatus:
    await request.app.state.demo.start(payload.scenario, payload.speed, payload.reset)
    return DemoStatus(**request.app.state.demo.status())


@router.post("/demo/stop", response_model=DemoStatus)
async def stop_demo(request: Request) -> DemoStatus:
    await request.app.state.demo.stop()
    return DemoStatus(**request.app.state.demo.status())


@router.post("/reset")
def reset_data(db: Session = Depends(get_db)) -> dict:
    db.query(Alert).delete()
    db.query(FlowWindow).delete()
    db.commit()
    return {"status": "reset"}


