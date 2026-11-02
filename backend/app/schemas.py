from datetime import datetime

from pydantic import BaseModel, Field


class FeatureOut(BaseModel):
    name: str
    label: str
    value: float
    baseline: float
    z_score: float
    direction: str


class FlowWindowOut(BaseModel):
    id: int
    source_ip: str
    window_start: datetime
    window_end: datetime
    packet_count: int
    byte_count: int
    flow_count: int
    score: float
    is_anomaly: bool
    features: dict[str, float | int]


class AlertOut(BaseModel):
    id: int
    flow_window_id: int
    source_ip: str
    severity: str
    score: float
    title: str
    reasons: list[FeatureOut]
    status: str
    created_at: datetime
    updated_at: datetime


class AlertDetail(AlertOut):
    flow: FlowWindowOut


class AlertUpdate(BaseModel):
    status: str = Field(pattern="^(new|acknowledged|benign)$")


class TimelinePoint(BaseModel):
    timestamp: datetime
    max_score: float
    packets: int
    bytes: int
    sources: int


class SummaryOut(BaseModel):
    packets_per_second: float
    active_sources: int
    total_windows: int
    alerts_last_15m: int
    alert_ratio: float
    model_threshold: float
    demo_running: bool
    demo_scenario: str | None
    timeline: list[TimelinePoint]


class ModelInfoOut(BaseModel):
    model_type: str
    feature_count: int
    training_windows: int
    threshold_score: float
    features: list[str]
    trained_at: str


class DemoStart(BaseModel):
    scenario: str = Field(default="mixed", pattern="^(normal|mixed)$")
    speed: float = Field(default=1.0, ge=0.25, le=5.0)
    reset: bool = True


class DemoStatus(BaseModel):
    running: bool
    scenario: str | None = None
    windows_delivered: int = 0
    message: str | None = None


