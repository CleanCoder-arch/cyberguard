# Stage 3A benchmark

From the CyberGuard workspace in PowerShell, run the evaluation with the raw URL and SMS files and the historical prepared `urls.csv` in `E:\data`.

```powershell
& .\venv\Scripts\python.exe .\evaluate_stage3a.py --data-dir E:\data
& .\venv\Scripts\python.exe -m pytest -q
```

The evaluation defaults to seed 42 and targets 70% train, 15% validation, and 15% test by class. It assigns whole groups, so exact proportions depend on the sizes and labels of the groups. The raw files preserve the original class frequencies and duplicate rows. URLs use the app normalizer and the bundled Public Suffix List, including private suffixes. SMS uses the app's whitespace trimming for model input, with separate message-template normalization and similarity matching for grouping. The benchmark labels are `good` and `bad` for URLs and `ham` and `spam` for SMS.

The new logistic-regression baselines fit preprocessing and model parameters on the training rows. Validation uses the baseline classifiers' default decision rule. Average precision uses positive-class probabilities. Confusion matrices list the negative class first on both axes, with actual labels on rows and predicted labels on columns. The test rows are reserved for the final comparison.

Each completed run prints its output directory under `data\stage3a`. The run directory contains these artifacts.

| File | Contents |
| --- | --- |
| `report.json` | Seed, data hashes, dependency versions, grouping rules, per-split class counts, overlap audits, and validation metrics |
| `historical.json` | Dashboard scores and the independent rerun of the historical URL experiment |
| `url_assignments.csv`, `sms_assignments.csv` | Source record IDs, labels, splits, group keys, and exact-duplicate hashes |
| `url_excluded.csv`, `sms_excluded.csv` | Every excluded source record ID and the validation reason |
| `url_hybrid_baseline.joblib`, `sms_baseline.joblib` | Stage 3A models and fitted preprocessing artifacts |

Source record IDs are 1-based CSV record ordinals after the header. Quoted multiline fields count as a single record. The file hashes identify the inputs to which these IDs refer.

## Stage 3A results

| Validation benchmark | Precision | Recall | F1 | Average precision | Confusion matrix |
| --- | ---: | ---: | ---: | ---: | --- |
| URL maliciousness detection | 88.24% | 88.94% | 88.59% | 95.77% | `[[56241, 2645], [2470, 19853]]` |
| SMS spam detection | 94.64% | 94.64% | 94.64% | 98.30% | `[[718, 6], [6, 106]]` |

| Split | URL good | URL bad | SMS ham | SMS spam |
| --- | ---: | ---: | ---: | ---: |
| Train | 274,800 | 104,175 | 3,377 | 523 |
| Validation | 58,886 | 22,323 | 724 | 112 |
| Test | 58,886 | 22,323 | 724 | 112 |

All three split pairs had zero shared URL registrable groups, hostnames, and duplicate hashes, and zero shared SMS template groups and duplicate hashes.

URL validation excluded 7,953 rows. The largest category was whitespace, control characters, or backslashes (7,742), followed by invalid hostname (153), unsupported scheme (22), invalid user information (15), invalid IPv4 address (9), invalid hostname or port (8), and malformed HTTP(S) scheme delimiter (4). SMS validation excluded zero rows. The run's exclusion CSVs contain the corresponding source record ordinals and reasons.

## Historical URL reproduction

```powershell
& .\venv\Scripts\python.exe .\evaluate_url_domain_split.py --data E:\data\urls.csv
```

The historical evaluator reproduced the dashboard's 93.53% F1. Its 39,883 training rows and 10,117 test rows shared zero exact hostnames and 576 registrable groups. The historical evaluation refits a model under the old protocol. The shipped models may have seen Stage 3A rows, so the historical figures are recorded independently of the new validation scores.
