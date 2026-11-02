from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _env_path(name: str, default: Path) -> Path:
    return Path(os.environ.get(name, str(default))).resolve()


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except ValueError:
        return default


@dataclass(slots=True)
class Settings:
    app_name: str = "NetSentry AI"
    data_dir: Path = field(default_factory=lambda: _env_path("NETSENTRY_DATA_DIR", PROJECT_ROOT / "data"))
    database_path: Path | None = None
    model_path: Path | None = None
    frontend_dist: Path = PROJECT_ROOT / "frontend" / "dist"
    window_seconds: int = field(default_factory=lambda: _env_int("NETSENTRY_WINDOW_SECONDS", 5))
    min_window_packets: int = field(default_factory=lambda: _env_int("NETSENTRY_MIN_WINDOW_PACKETS", 10))
    alert_cooldown_seconds: int = field(
        default_factory=lambda: _env_int("NETSENTRY_ALERT_COOLDOWN_SECONDS", 20)
    )
    normal_pcap: Path | None = None
    mixed_pcap: Path | None = None
    demo_interval_seconds: float = field(
        default_factory=lambda: _env_float("NETSENTRY_DEMO_INTERVAL_SECONDS", 0.65)
    )
    cors_origins: list[str] = field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ]
    )

    def __post_init__(self) -> None:
        self.database_path = self.database_path or self.data_dir / "netsentry.db"
        self.model_path = self.model_path or self.data_dir / "models" / "isolation_forest.joblib"
        self.normal_pcap = self.normal_pcap or self.data_dir / "samples" / "normal.pcap"
        self.mixed_pcap = self.mixed_pcap or self.data_dir / "samples" / "mixed.pcap"
        self.ensure_dirs()

    @property
    def database_url(self) -> str:
        assert self.database_path is not None
        return f"sqlite:///{self.database_path.as_posix()}"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        if self.database_path:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
        if self.model_path:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
        if self.normal_pcap:
            self.normal_pcap.parent.mkdir(parents=True, exist_ok=True)


settings = Settings()

