"""Read published Stage 3B metrics with their matching validation lock."""

import json
from math import isfinite
from pathlib import Path

from evaluate_stage3b import MODEL_NAMES, TASKS


PROJECT_DIR = Path(__file__).resolve().parent
BENCHMARK_DIR = PROJECT_DIR / "data" / "stage3b"
BUNDLED_BENCHMARK_DIR = PROJECT_DIR / "benchmarks" / "stage3b"
MODEL_FEATURES = {
    "sms": {"logistic": "Word TF-IDF", "linear_svm_calibrated": "Word TF-IDF"},
    "url": {
        "logistic": "Character TF-IDF and lexical features",
        "linear_svm_calibrated": "Character TF-IDF and lexical features",
        "lexical_logistic": "Lexical features only",
        "lexical_tree": "Lexical features only",
    },
}
RATE_METRICS = ("accuracy", "precision", "recall", "f1", "average_precision", "false_positive_rate")


def _number(value, *, maximum=None):
    if type(value) not in (float, int) or not isfinite(value) or value < 0:
        raise ValueError("Benchmark metrics must be finite, nonnegative numbers.")
    if maximum is not None and value > maximum:
        raise ValueError("Benchmark proportions must be between zero and one.")
    return float(value)


def _load_run(directory):
    lock = json.loads((directory / "locked_selection.json").read_text(encoding="utf-8"))
    report = json.loads((directory / "comparison.json").read_text(encoding="utf-8"))
    audit = report["split_audit"]
    selection = lock["validation_selection"]
    held_out = report["held_out_test"]
    if (
        type(lock["seed"]) is not int
        or lock["seed"] != audit["seed"]
        or lock["stage3a_report"] != audit["stage3a_report"]
        or lock["baseline_artifacts"] != report["baseline_artifacts"]
        or lock["target_false_positive_rate"] != report["target_false_positive_rate"]
        or selection != report["validation_selection"]
        or set(selection) != set(TASKS)
        or set(held_out) != set(TASKS)
    ):
        raise ValueError("Benchmark report and validation lock do not match.")

    tasks = {}
    for task, (title, _) in TASKS.items():
        candidates = selection[task]["candidates"]
        models = held_out[task]
        features = MODEL_FEATURES[task]
        winner = selection[task]["selected_model"]
        if set(candidates) != set(features) or set(models) != set(features) or winner not in features:
            raise ValueError("Benchmark report does not include the locked candidates.")

        rows = []
        for name, model_features in features.items():
            metrics = models[name]
            threshold = _number(candidates[name]["threshold"])
            if _number(metrics["threshold"]) != threshold:
                raise ValueError("A held-out threshold differs from its validation lock.")
            latency = metrics["inference_latency"]
            rows.append({
                "model": MODEL_NAMES[name],
                "features": model_features,
                "selected": name == winner,
                "threshold": threshold,
                **{metric: _number(metrics[metric], maximum=1) for metric in RATE_METRICS},
                "median_ms": _number(latency["median_ms"]),
                "p95_ms": _number(latency["p95_ms"]),
            })
        tasks[task] = {"label": title, "selected_model": MODEL_NAMES[winner], "models": rows}

    return {
        "run": directory.name,
        "seed": lock["seed"],
        "target_false_positive_rate": _number(lock["target_false_positive_rate"], maximum=1),
        "tasks": tasks,
    }


def _report_order(directory):
    try:
        modified = (directory / "comparison.json").stat().st_mtime_ns
    except OSError:
        modified = 0
    return modified, directory.name


def _load_benchmark_directory(path):
    path = Path(path)
    try:
        if (path / "comparison.json").is_file() or (path / "locked_selection.json").is_file():
            runs = [path]
        else:
            runs = sorted(path.glob("run-*"), key=_report_order, reverse=True)
    except OSError:
        return None

    for directory in runs:
        try:
            return _load_run(directory)
        except (OSError, ValueError, KeyError, TypeError, OverflowError):
            continue
    return None


def load_stage3b_benchmark(path=None):
    """Read a specific run or use the bundled aggregate when local results are absent."""
    if path is not None:
        return _load_benchmark_directory(path)
    return _load_benchmark_directory(BENCHMARK_DIR) or _load_benchmark_directory(BUNDLED_BENCHMARK_DIR)
