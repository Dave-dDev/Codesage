from __future__ import annotations

import asyncio
from itertools import groupby

from sqlalchemy import delete

from ..capture.reader import read_pcap
from ..config import settings
from ..db import SessionLocal
from ..engine import DetectionEngine
from ..features.extractor import WindowFeatureExtractor
from ..models import Alert, FlowWindow
from ..ws import ConnectionManager


class DemoRunner:
    def __init__(self, engine: DetectionEngine, broadcaster: ConnectionManager) -> None:
        self.engine = engine
        self.broadcaster = broadcaster
        self._task: asyncio.Task | None = None
        self.running = False
        self.scenario: str | None = None
        self.windows_delivered = 0

    def status(self) -> dict:
        return {
            "running": self.running,
            "scenario": self.scenario,
            "windows_delivered": self.windows_delivered,
        }

    async def start(self, scenario: str, speed: float = 1.0, reset: bool = True) -> None:
        await self.stop()
        if reset:
            with SessionLocal() as db:
                db.execute(delete(Alert))
                db.execute(delete(FlowWindow))
                db.commit()
            self.engine.reset_state()

        pcap_path = settings.mixed_pcap if scenario == "mixed" else settings.normal_pcap
        packets = read_pcap(pcap_path)
        windows = WindowFeatureExtractor(
            settings.window_seconds, settings.min_window_packets
        ).extract(packets)
        self.running = True
        self.scenario = scenario
        self.windows_delivered = 0
        await self.broadcaster.broadcast("demo", self.status())
        self._task = asyncio.create_task(self._run(windows, speed))

    async def stop(self) -> None:
        task = self._task
        self._task = None
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        if self.running:
            self.running = False
            await self.broadcaster.broadcast("demo", self.status())

    async def _run(self, windows: list, speed: float) -> None:
        try:
            for _, batch in groupby(windows, key=lambda item: item.window_start):
                await asyncio.sleep(settings.demo_interval_seconds / max(speed, 0.25))
                batch_list = list(batch)
                for window in batch_list:
                    await self.engine.ingest(window)
                    self.windows_delivered += 1
                await self.broadcaster.broadcast("demo", self.status())
        finally:
            self.running = False
            await self.broadcaster.broadcast("demo", self.status())


