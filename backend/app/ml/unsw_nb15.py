from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DATASET = PROJECT_ROOT / "UNSW_NB15_testing-set.parquet"
DEFAULT_MODEL = PROJECT_ROOT / "data" / "models" / "unsw_nb15_random_forest.joblib"
DEFAULT_METRICS = PROJECT_ROOT / "docs" / "unsw_nb15_metrics.json"

CATEGORICAL_FEATURES = ["proto", "service", "state"]
LABEL_COLUMN = "label"
ATTACK_COLUMN = "attack_cat"
RANDOM_STATE = 42


@dataclass(slots=True)
class DatasetAudit:
    source: str
    original_rows: int
    duplicate_rows_removed: int
    unique_rows: int
    benign_rows: int
    attack_rows: int
    null_values: int
    infinite_values: int
    attack_categories: dict[str, int]


def load_unsw_dataset(dataset_path: Path) -> tuple[pd.DataFrame, DatasetAudit]:
    if not dataset_path.exists():
        raise FileNotFoundError(f"UNSW-NB15 dataset not found: {dataset_path}")

    original = pd.read_parquet(dataset_path)
    required = {LABEL_COLUMN, ATTACK_COLUMN, *CATEGORICAL_FEATURES}
    missing = required.difference(original.columns)
    if missing:
        raise ValueError(f"Dataset is missing required columns: {sorted(missing)}")

    original_rows = len(original)
    duplicates = int(original.duplicated().sum())
    frame = original.drop_duplicates().reset_index(drop=True).copy()

    for column in CATEGORICAL_FEATURES:
        frame[column] = frame[column].astype(str).fillna("unknown")
    frame[ATTACK_COLUMN] = frame[ATTACK_COLUMN].astype(str).fillna("Normal")
    frame[LABEL_COLUMN] = frame[LABEL_COLUMN].astype(int)

    numeric = frame.select_dtypes(include=np.number)
    audit = DatasetAudit(
        source=dataset_path.name,
        original_rows=original_rows,
        duplicate_rows_removed=duplicates,
        unique_rows=len(frame),
        benign_rows=int((frame[LABEL_COLUMN] == 0).sum()),
        attack_rows=int((frame[LABEL_COLUMN] == 1).sum()),
        null_values=int(frame.isna().sum().sum()),
        infinite_values=int(np.isinf(numeric.to_numpy()).sum()),
        attack_categories={
            str(key): int(value)
            for key, value in frame[ATTACK_COLUMN].value_counts().items()
        },
    )
    return frame, audit


def build_model() -> Pipeline:
    preprocessing = ColumnTransformer(
        transformers=[
            (
                "categorical",
                OneHotEncoder(
                    handle_unknown="ignore",
                    min_frequency=20,
                    sparse_output=False,
                ),
                CATEGORICAL_FEATURES,
            )
        ],
        remainder="passthrough",
        verbose_feature_names_out=True,
    )
    classifier = RandomForestClassifier(
        n_estimators=350,
        class_weight="balanced_subsample",
        min_samples_leaf=2,
        max_features="sqrt",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    return Pipeline([("preprocess", preprocessing), ("classifier", classifier)])


def _threshold_candidates(probabilities: np.ndarray) -> np.ndarray:
    quantiles = np.quantile(probabilities, np.linspace(0.01, 0.99, 199))
    return np.unique(np.clip(quantiles, 0.01, 0.99))


def _select_threshold(probabilities: np.ndarray, labels: np.ndarray) -> tuple[float, float]:
    best_threshold = 0.5
    best_f1 = -1.0
    for threshold in _threshold_candidates(probabilities):
        predictions = probabilities >= threshold
        _, _, f1, _ = precision_recall_fscore_support(
            labels, predictions, average="binary", zero_division=0
        )
        if f1 > best_f1:
            best_f1 = float(f1)
            best_threshold = float(threshold)
    return best_threshold, best_f1


def _metrics_at_threshold(
    labels: np.ndarray, probabilities: np.ndarray, threshold: float
) -> dict:
    predictions = probabilities >= threshold
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, average="binary", zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    false_positive_rate = float(fp / (fp + tn)) if (fp + tn) else 0.0
    return {
        "threshold": round(float(threshold), 6),
        "accuracy": round(float((predictions == labels).mean()), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "true_positive": int(tp),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_negative": int(tn),
    }


def _top_importances(pipeline: Pipeline, limit: int = 20) -> list[dict]:
    preprocessor: ColumnTransformer = pipeline.named_steps["preprocess"]
    classifier: RandomForestClassifier = pipeline.named_steps["classifier"]
    names = preprocessor.get_feature_names_out()
    ranking = np.argsort(classifier.feature_importances_)[::-1][:limit]
    return [
        {
            "feature": str(names[index]),
            "importance": round(float(classifier.feature_importances_[index]), 5),
        }
        for index in ranking
    ]


def train_unsw_model(
    dataset_path: Path = DEFAULT_DATASET,
    model_path: Path = DEFAULT_MODEL,
    metrics_path: Path = DEFAULT_METRICS,
) -> dict:
    frame, audit = load_unsw_dataset(dataset_path)
    feature_columns = [
        column for column in frame.columns if column not in {LABEL_COLUMN, ATTACK_COLUMN}
    ]
    labels = frame[LABEL_COLUMN].to_numpy()
    attack_categories = frame[ATTACK_COLUMN].astype(str).to_numpy()
    features = frame[feature_columns]

    strata = frame[LABEL_COLUMN].astype(str) + "__" + frame[ATTACK_COLUMN].astype(str)
    train_index, holdout_index = train_test_split(
        np.arange(len(frame)),
        test_size=0.40,
        random_state=RANDOM_STATE,
        stratify=strata,
    )
    validation_index, test_index = train_test_split(
        holdout_index,
        test_size=0.625,
        random_state=RANDOM_STATE,
        stratify=strata.iloc[holdout_index],
    )

    pipeline = build_model()
    pipeline.fit(features.iloc[train_index], labels[train_index])

    validation_probabilities = pipeline.predict_proba(features.iloc[validation_index])[:, 1]
    validation_labels = labels[validation_index]
    selected_threshold, validation_f1 = _select_threshold(
        validation_probabilities, validation_labels
    )

    test_probabilities = pipeline.predict_proba(features.iloc[test_index])[:, 1]
    test_labels = labels[test_index]
    test_categories = attack_categories[test_index]
    selected_test_metrics = _metrics_at_threshold(
        test_labels, test_probabilities, selected_threshold
    )

    operating_points = {}
    validation_benign_scores = validation_probabilities[validation_labels == 0]
    for target_fpr in (0.01, 0.05, 0.10):
        threshold = float(np.quantile(validation_benign_scores, 1 - target_fpr))
        operating_points[f"target_fpr_{int(target_fpr * 100)}pct"] = (
            _metrics_at_threshold(test_labels, test_probabilities, threshold)
        )

    selected_predictions = test_probabilities >= selected_threshold
    per_category = {}
    for category in sorted(set(test_categories[test_labels == 1])):
        mask = test_categories == category
        per_category[category] = {
            "rows": int(mask.sum()),
            "recall": round(float(selected_predictions[mask].mean()), 4),
        }

    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": asdict(audit),
        "split": {
            "strategy": "stratified row-level holdout; duplicates removed before splitting",
            "train_rows": int(len(train_index)),
            "validation_rows": int(len(validation_index)),
            "test_rows": int(len(test_index)),
            "train_attack_rows": int((labels[train_index] == 1).sum()),
            "validation_attack_rows": int((labels[validation_index] == 1).sum()),
            "test_attack_rows": int((labels[test_index] == 1).sum()),
        },
        "model": {
            "name": "RandomForestClassifier",
            "n_estimators": 350,
            "class_weight": "balanced_subsample",
            "feature_columns": feature_columns,
        },
        "validation": {
            "selected_threshold": round(selected_threshold, 6),
            "f1_at_selected_threshold": round(validation_f1, 4),
            "roc_auc": round(
                float(roc_auc_score(validation_labels, validation_probabilities)), 4
            ),
            "pr_auc": round(
                float(average_precision_score(validation_labels, validation_probabilities)), 4
            ),
        },
        "test": {
            "roc_auc": round(float(roc_auc_score(test_labels, test_probabilities)), 4),
            "pr_auc": round(
                float(average_precision_score(test_labels, test_probabilities)), 4
            ),
            **selected_test_metrics,
        },
        "operating_points": operating_points,
        "per_attack_category": per_category,
        "top_feature_importances": _top_importances(pipeline),
        "caveat": (
            "Only the UNSW-NB15 testing split was supplied. This benchmark trains and "
            "evaluates on random row-level partitions of that test file after duplicate "
            "removal. It is not a replacement for training on the official training split, "
            "and it does not validate deployment performance. Multiple rows may originate "
            "from the same original capture despite deduplication."
        ),
    }

    model_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": pipeline,
            "feature_columns": feature_columns,
            "threshold": selected_threshold,
            "metrics": metrics,
        },
        model_path,
    )
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the UNSW-NB15 flow benchmark")
    parser.add_argument("--data", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--model-out", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--metrics-out", type=Path, default=DEFAULT_METRICS)
    args = parser.parse_args()

    metrics = train_unsw_model(args.data, args.model_out, args.metrics_out)
    test = metrics["test"]
    print("UNSW-NB15 training complete")
    print(f"  unique rows        {metrics['dataset']['unique_rows']}")
    print(f"  duplicates dropped {metrics['dataset']['duplicate_rows_removed']}")
    print(f"  validation F1      {metrics['validation']['f1_at_selected_threshold']}")
    print(f"  test ROC AUC       {test['roc_auc']}")
    print(f"  test PR AUC        {test['pr_auc']}")
    print(f"  test precision     {test['precision']}")
    print(f"  test recall        {test['recall']}")
    print(f"  test F1            {test['f1']}")
    print(f"  test FPR           {test['false_positive_rate']}")
    print(f"  model              {args.model_out}")
    print(f"  metrics            {args.metrics_out}")


if __name__ == "__main__":
    main()
