from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .api.routes import router
from .config import settings
from .db import init_db
from .demo.generator import ensure_demo_data
from .demo.runner import DemoRunner
from .engine import DetectionEngine
from .ml.detector import load_or_train_detector
from .ws import ConnectionManager


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    ensure_demo_data()
    detector = await asyncio.to_thread(load_or_train_detector)
    broadcaster = ConnectionManager()
    engine = DetectionEngine(detector, broadcaster)
    demo = DemoRunner(engine, broadcaster)
    app.state.detector = detector
    app.state.broadcaster = broadcaster
    app.state.engine = engine
    app.state.demo = demo
    yield
    await demo.stop()


app = FastAPI(
    title="NetSentry AI",
    description="AI-assisted network traffic anomaly detection and triage.",
    version="1.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router)


@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket) -> None:
    broadcaster: ConnectionManager = websocket.app.state.broadcaster
    await broadcaster.connect(websocket)
    try:
        await websocket.send_json(
            {"type": "hello", "data": {"service": "NetSentry AI", "demo": websocket.app.state.demo.status()}}
        )
        while True:
            await asyncio.sleep(15)
            await websocket.send_json({"type": "ping", "data": {}})
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        await broadcaster.disconnect(websocket)


if settings.frontend_dist.exists():
    app.mount("/", StaticFiles(directory=settings.frontend_dist, html=True), name="frontend")
else:
    @app.get("/")
    def root() -> JSONResponse:
        return JSONResponse(
            {
                "service": "NetSentry AI API",
                "docs": "/docs",
                "message": "Frontend is not built yet. Run the Vite dev server or build frontend/dist.",
            }
        )
