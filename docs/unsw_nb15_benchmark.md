# UNSW-NB15 Flow Benchmark

This benchmark uses the supplied `UNSW_NB15_testing-set.parquet` file. It is deliberately kept
separate from the live NetSentry PCAP pipeline because the dataset contains aggregated flow features
but no packet timestamps, IP addresses, or ports.

## Dataset audit

| Metric | Value |
|---|---:|
| Original rows | 82,332 |
| Exact duplicate rows removed | 32,361 |
| Unique rows | 49,971 |
| Benign rows | 31,610 |
| Attack rows | 18,361 |
| Null values | 0 |
| Infinite values | 0 |
| Categorical fields | `proto`, `service`, `state` |

Attack categories after deduplication:

| Category | Rows |
|---|---:|
| Normal | 31,610 |
| Exploits | 7,482 |
| Fuzzers | 4,415 |
| Reconnaissance | 2,127 |
| Generic | 1,643 |
| DoS | 1,598 |
| Analysis | 386 |
| Shellcode | 370 |
| Backdoor | 296 |
| Worms | 44 |

## Why this is a separate benchmark

The UNSW-NB15 Parquet file contains precomputed flow attributes such as packet counts, byte counts,
TCP timing features, and categorical protocol/service/state fields. It does **not** contain:

- source or destination IP addresses
- source or destination ports
- packet timestamps
- individual packet records
- TCP flag values

NetSentry's live dashboard model is trained on 5-second, per-source packet windows. Those windows
cannot be reconstructed from this file without inventing missing network identifiers and timestamps.
For that reason, the UNSW model is stored separately and is not loaded by the live FastAPI dashboard.

## Training setup

- **Model:** Random Forest classifier
- **Trees:** 350
- **Class weighting:** `balanced_subsample`
- **Categorical encoding:** one-hot encoding; infrequent protocol values grouped with `min_frequency=20`
- **Duplicate policy:** exact duplicates removed before splitting
- **Split:** stratified row-level partitions
- **Random seed:** 42

| Split | Rows | Attack rows |
|---|---:|---:|
| Train | 29,982 | 11,016 |
| Validation | 7,495 | 2,754 |
| Test | 12,494 | 4,591 |

The classification threshold is selected on the validation split by maximizing F1 and then applied
unchanged to the test split.

## Test results

At the validation-selected threshold of `0.467277`:

| Metric | Value |
|---|---:|
| ROC AUC | 0.9724 |
| PR AUC | 0.9602 |
| Accuracy | 0.9062 |
| Precision | 0.8748 |
| Recall | 0.8691 |
| F1 | 0.8719 |
| False-positive rate | 7.23% |

The F1-optimal threshold produces a relatively high false-positive rate. For a security-monitoring
deployment, the lower-FPR operating point is often more relevant:

| Operating target | Threshold | Precision | Recall | F1 | Actual FPR |
|---|---:|---:|---:|---:|---:|
| 1% validation FPR | 0.7510 | 0.9765 | 0.7430 | 0.8439 | 1.04% |
| 5% validation FPR | 0.5333 | 0.9112 | 0.8449 | 0.8768 | 4.78% |
| 10% validation FPR | 0.3878 | 0.8323 | 0.9035 | 0.8664 | 10.58% |

Per-attack-category recall at the F1-selected threshold:

| Category | Test rows | Recall |
|---|---:|---:|
| Analysis | 97 | 100.0% |
| Backdoor | 74 | 98.7% |
| DoS | 399 | 94.2% |
| Exploits | 1,871 | 95.8% |
| Fuzzers | 1,104 | 58.8% |
| Generic | 411 | 97.6% |
| Reconnaissance | 532 | 98.3% |
| Shellcode | 92 | 73.9% |
| Worms | 11 | 100.0% |

Fuzzers and shellcode are the weakest categories. Fuzzers are intentionally varied and may resemble
benign traffic in the available aggregate features.

## Reproduce

From the repository root:

```powershell
.\.venv\Scripts\Activate.ps1
Set-Location backend
python -m app.ml.unsw_nb15
```

Outputs:

```text
data/models/unsw_nb15_random_forest.joblib
docs/unsw_nb15_metrics.json
```

## Important limitations

1. **Only the official testing split was supplied.** Training used random row-level partitions of
   that test file. The missing official training split should be added for a valid benchmark.
2. Multiple rows may originate from the same original capture even after exact duplicate removal.
   Random row-level splitting can therefore overestimate generalization.
3. The resulting model cannot be used by the current PCAP dashboard without a new flow-level feature
   adapter.
4. A production model should be trained on the official UNSW-NB15 training split or, preferably, raw
   PCAP from the target environment, with train/test separation by capture or time period.
