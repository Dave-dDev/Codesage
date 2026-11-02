from pathlib import Path

import joblib
import pytest

from app.ml.unsw_nb15 import DEFAULT_DATASET, DEFAULT_METRICS, DEFAULT_MODEL, load_unsw_dataset


pytestmark = pytest.mark.skipif(
    not DEFAULT_DATASET.exists() or not DEFAULT_MODEL.exists(),
    reason="UNSW-NB15 dataset or trained artifact is not present",
)


def test_unsw_dataset_is_audited_and_deduplicated() -> None:
    frame, audit = load_unsw_dataset(DEFAULT_DATASET)
    assert audit.original_rows == 82_332
    assert audit.duplicate_rows_removed == 32_361
    assert audit.unique_rows == 49_971
    assert audit.benign_rows == 31_610
    assert audit.attack_rows == 18_361
    assert len(frame) == audit.unique_rows


def test_unsw_model_artifact_can_score_flows() -> None:
    frame, _ = load_unsw_dataset(DEFAULT_DATASET)
    bundle = joblib.load(DEFAULT_MODEL)
    scores = bundle["model"].predict_proba(frame[bundle["feature_columns"]].head(8))[:, 1]
    assert scores.shape == (8,)
    assert ((scores >= 0) & (scores <= 1)).all()
    assert DEFAULT_METRICS.exists()
