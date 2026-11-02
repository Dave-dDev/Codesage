from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from ..capture.reader import read_pcap
from ..config import settings
from ..demo.generator import ensure_demo_data
from ..features.extractor import FEATURE_LABELS, FEATURE_NAMES, FeatureWindow, WindowFeatureExtractor


DEVIATION_GATE = 50.0


@dataclass(slots=True)
class FeatureExplanation:
    name: str
    label: str
    value: float
    baseline: float
    z_score: float
    direction: str


@dataclass(slots=True)
class DetectionResult:
    raw_score: float
    model_score: float
    deviation_score: float
    score: float
    max_deviation: float
    is_anomaly: bool
    explanations: list[FeatureExplanation]


class AnomalyDetector:
    def __init__(self, artifact: dict) -> None:
        self.artifact = artifact
        self.model: IsolationForest = artifact["model"]
        self.feature_names: list[str] = artifact["feature_names"]
        self.threshold_raw: float = float(artifact["threshold_raw"])
        self.threshold_score: float = float(artifact["threshold_score"])
        self.median = np.asarray(artifact["median"], dtype=float)
        self.scale = np.asarray(artifact["scale"], dtype=float)

    @property
    def info(self) -> dict:
        return {
            "model_type": "Isolation Forest + deviation gate",
            "feature_count": len(self.feature_names),
            "training_windows": int(self.artifact["training_windows"]),
            "threshold_score": self.threshold_score,
            "features": self.feature_names,
            "trained_at": str(self.artifact["trained_at"]),
        }

    def score(self, window: FeatureWindow) -> DetectionResult:
        vector = np.asarray([window.vector(self.feature_names)], dtype=float)
        raw_score = float(-self.model.score_samples(vector)[0])
        model_score = 0.0
        if self.threshold_raw > 0:
            model_score = float(np.clip(100.0 * raw_score / (2.0 * self.threshold_raw), 0, 100))

        deviations = (vector[0] - self.median) / self.scale
        absolute_deviations = np.abs(deviations)
        max_deviation = float(absolute_deviations.max())
        deviation_score = float(
            np.clip(100.0 * np.log10(max_deviation + 1.0) / np.log10(1000.0), 0, 100)
        )

        # The model proposes candidates; the deviation gate verifies that the window is
        # meaningfully separated from the training baseline. This reduces edge-window noise.
        is_anomaly = raw_score >= self.threshold_raw and max_deviation >= DEVIATION_GATE

        if is_anomaly:
            score = 0.25 * model_score + 0.75 * deviation_score
        else:
            score = min(49.5, model_score)
        score = round(float(np.clip(score, 0, 100)), 2)

        top_indices = np.argsort(absolute_deviations)[-3:][::-1]
        explanations = []
        for index in top_indices:
            name = self.feature_names[index]
            explanations.append(
                FeatureExplanation(
                    name=name,
                    label=FEATURE_LABELS.get(name, name),
                    value=round(float(vector[0, index]), 3),
                    baseline=round(float(self.median[index]), 3),
                    z_score=round(float(deviations[index]), 2),
                    direction="above" if deviations[index] >= 0 else "below",
                )
            )

        return DetectionResult(
            raw_score=raw_score,
            model_score=round(model_score, 2),
            deviation_score=round(deviation_score, 2),
            score=score,
            max_deviation=round(max_deviation, 2),
            is_anomaly=is_anomaly,
            explanations=explanations,
        )


def train_detector(normal_pcap: Path | None = None) -> AnomalyDetector:
    ensure_demo_data()
    pcap_path = normal_pcap or settings.normal_pcap
    assert pcap_path is not None
    packets = read_pcap(pcap_path)
    windows = WindowFeatureExtractor(
        settings.window_seconds, settings.min_window_packets
    ).extract(packets)
    if len(windows) < 20:
        raise RuntimeError("Not enough normal windows to train the detector")

    matrix = np.asarray([window.vector(FEATURE_NAMES) for window in windows], dtype=float)
    model = IsolationForest(
        n_estimators=320,
        contamination=0.01,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(matrix)
    raw_scores = -model.score_samples(matrix)
    threshold_raw = float(np.quantile(raw_scores, 0.99))
    median = np.median(matrix, axis=0)
    mad = np.median(np.abs(matrix - median), axis=0)
    std = np.std(matrix, axis=0)
    scale = np.maximum(mad * 1.4826, std * 0.20)
    scale = np.where(scale < 1e-6, 1.0, scale)

    artifact = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "threshold_raw": threshold_raw,
        "threshold_score": 50.0,
        "median": median,
        "scale": scale,
        "training_windows": len(windows),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "training_raw_p95": float(np.quantile(raw_scores, 0.95)),
        "training_raw_p99": float(np.quantile(raw_scores, 0.99)),
        "deviation_gate": DEVIATION_GATE,
    }
    assert settings.model_path is not None
    settings.model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, settings.model_path)
    return AnomalyDetector(artifact)


def load_or_train_detector(force_retrain: bool = False) -> AnomalyDetector:
    if not force_retrain and settings.model_path and settings.model_path.exists():
        try:
            artifact = joblib.load(settings.model_path)
            if (
                artifact.get("feature_names") == FEATURE_NAMES
                and "deviation_gate" in artifact
            ):
                return AnomalyDetector(artifact)
        except Exception:
            pass
    return train_detector()
