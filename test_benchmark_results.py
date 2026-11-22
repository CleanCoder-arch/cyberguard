from copy import deepcopy
import json
import os

import benchmark_results
from benchmark_results import load_stage3b_benchmark


def make_benchmark():
    candidate_names = {
        "sms": ("logistic", "linear_svm_calibrated"),
        "url": ("logistic", "linear_svm_calibrated", "lexical_logistic", "lexical_tree"),
    }
    lock = {
        "seed": 42,
        "stage3a_report": "stage3a-digest",
        "baseline_artifacts": {"sms": "sms-digest", "url": "url-digest"},
        "target_false_positive_rate": 0.01,
        "validation_selection": {
            task: {
                "selected_model": "linear_svm_calibrated" if task == "sms" else "logistic",
                "candidates": {name: {"threshold": index / 10} for index, name in enumerate(names, 2)},
            }
            for task, names in candidate_names.items()
        },
    }
    report = {
        "split_audit": {"seed": lock["seed"], "stage3a_report": lock["stage3a_report"]},
        "baseline_artifacts": deepcopy(lock["baseline_artifacts"]),
        "target_false_positive_rate": lock["target_false_positive_rate"],
        "validation_selection": deepcopy(lock["validation_selection"]),
        "held_out_test": {
            task: {
                name: {
                    "threshold": locked["threshold"],
                    "accuracy": 0.97,
                    "precision": 0.91,
                    "recall": 0.9,
                    "f1": 0.9,
                    "average_precision": 0.94,
                    "false_positive_rate": 0.02,
                    "inference_latency": {"median_ms": 0.4, "p95_ms": 0.8},
                }
                for name, locked in selection["candidates"].items()
            }
            for task, selection in lock["validation_selection"].items()
        },
    }
    return report, lock


def write_run(directory, report, lock):
    directory.mkdir()
    (directory / "comparison.json").write_text(json.dumps(report), encoding="utf-8")
    (directory / "locked_selection.json").write_text(json.dumps(lock), encoding="utf-8")


def test_read_locked_run_and_label_benchmarked_candidates(tmp_path):
    run = tmp_path / "run-fixture"
    write_run(run, *make_benchmark())

    benchmark = load_stage3b_benchmark(tmp_path)
    assert benchmark == load_stage3b_benchmark(run)
    assert benchmark["run"] == run.name
    assert benchmark["seed"] == 42
    assert benchmark["target_false_positive_rate"] == 0.01
    sms = benchmark["tasks"]["sms"]
    assert sms["label"] == "SMS spam detection"
    assert len(sms["models"]) == 2
    selected = next(row for row in sms["models"] if row["selected"])
    assert selected["model"] == sms["selected_model"] == "Calibrated linear SVM"
    assert selected["threshold"] == 0.3
    assert selected["features"] == "Word TF-IDF"
    assert selected["accuracy"] == 0.97
    assert selected["false_positive_rate"] == 0.02
    assert selected["p95_ms"] == 0.8
    url = benchmark["tasks"]["url"]
    assert url["selected_model"] == "Stage 3A logistic regression"
    assert len(url["models"]) == 4
    assert sum(row["selected"] for row in url["models"]) == 1


def test_missing_or_mismatched_lock_hides_results(tmp_path):
    assert load_stage3b_benchmark(tmp_path / "missing") is None
    run = tmp_path / "run-fixture"
    report, lock = make_benchmark()
    write_run(run, report, lock)
    lock_path = run / "locked_selection.json"
    lock_path.unlink()
    assert load_stage3b_benchmark(tmp_path) is None

    lock["seed"] += 1
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    assert load_stage3b_benchmark(tmp_path) is None


def test_newest_valid_report_wins_and_threshold_drift_is_rejected(tmp_path):
    first = tmp_path / "run-first"
    second = tmp_path / "run-second"
    report, lock = make_benchmark()
    write_run(first, report, lock)
    write_run(second, report, lock)
    first_report = first / "comparison.json"
    os.utime(first_report, (1_700_000_000, 1_700_000_000))
    assert load_stage3b_benchmark(tmp_path)["run"] == second.name

    report["held_out_test"]["url"]["logistic"]["threshold"] += 0.1
    (second / "comparison.json").write_text(json.dumps(report), encoding="utf-8")
    assert load_stage3b_benchmark(second) is None
    assert load_stage3b_benchmark(tmp_path)["run"] == first.name


def test_bundled_benchmark_loads_without_workspace_data(tmp_path, monkeypatch):
    monkeypatch.setattr(benchmark_results, "BENCHMARK_DIR", tmp_path / "missing")
    benchmark = load_stage3b_benchmark()
    assert benchmark["run"] == "run-1dtd87ks"
    assert benchmark["seed"] == 42

    sms = benchmark["tasks"]["sms"]
    selected = next(model for model in sms["models"] if model["selected"])
    assert sms["label"] == "SMS spam detection"
    assert selected["model"] == "Calibrated linear SVM"
    assert selected["recall"] == 0.9375
    assert round(selected["false_positive_rate"] * 100, 2) == 1.38

    url = benchmark["tasks"]["url"]
    selected = next(model for model in url["models"] if model["selected"])
    assert selected["model"] == "Stage 3A logistic regression"
    assert round(selected["recall"] * 100, 2) == 82.80
    assert round(selected["false_positive_rate"] * 100, 2) == 0.44
