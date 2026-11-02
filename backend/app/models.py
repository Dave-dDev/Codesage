from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class FlowWindow(Base):
    __tablename__ = "flow_windows"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    packet_count: Mapped[int] = mapped_column(Integer)
    byte_count: Mapped[int] = mapped_column(Integer)
    flow_count: Mapped[int] = mapped_column(Integer)
    score: Mapped[float] = mapped_column(Float, index=True)
    is_anomaly: Mapped[bool] = mapped_column(default=False, index=True)
    features_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    alert: Mapped["Alert | None"] = relationship(back_populates="flow", uselist=False)

    __table_args__ = (
        Index("ix_flow_source_window", "source_ip", "window_start"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    flow_window_id: Mapped[int] = mapped_column(ForeignKey("flow_windows.id"), unique=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    score: Mapped[float] = mapped_column(Float)
    title: Mapped[str] = mapped_column(String(160))
    reasons_json: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="new", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    flow: Mapped[FlowWindow] = relationship(back_populates="alert")
