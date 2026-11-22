"""Compare offline classifiers on the exact Stage 3A benchmark splits."""

import argparse
import json
import os
from importlib.metadata import version
from math import isclose
from pathlib import Path
from platform import platform, python_version
from tempfile import TemporaryDirectory

from threadpoolctl import threadpool_limits

from evaluate_stage3a import file_digest, write_json
from evaluate_url_domain_split import binary_metrics
from stage3b_data import load_verified_stage3a
from stage3b_metrics import measure_inference_latency, score_at_threshold, threshold_for_fpr
from stage3b_models import fit_candidates
from url_normalizer import normalize_url


TARGET_FPR = 0.01
MODEL_THREADS = 1
TASKS = {"sms": ("SMS spam detection", "text"), "url": ("URL maliciousness detection", "url")}
MODEL_NAMES = {
    "logistic": "Stage 3A logistic regression",
    "linear_svm_calibrated": "Calibrated linear SVM",
    "lexical_tree": "Lexical boosted trees",
    "lexical_logistic": "Lexical logistic regression",
}
BASELINE_FILES = {"sms": "sms_baseline.joblib", "url": "url_hybrid_baseline.joblib"}


def validate_candidates(candidates, validation, column, baseline_reference):
    comparisons = {}
    for name, candidate in candidates.items():
        probabilities = candidate.score(validation[column])
        if name == "logistic":
            baseline_metrics = binary_metrics(validation["label"], probabilities > 0.5, probabilities)
            same_matrix = baseline_metrics["confusion_matrix"] == baseline_reference["confusion_matrix"]
            same_scores = all(
                isclose(value, baseline_reference[key], rel_tol=0, abs_tol=1e-10)
                for key, value in baseline_metrics.items() if key != "confusion_matrix"
            )
            if not (same_matrix and same_scores):
                raise ValueError("The logistic artifact does not reproduce its Stage 3A validation metrics.")
        threshold = threshold_for_fpr(validation["label"], probabilities, TARGET_FPR)
        comparisons[name] = {
            "threshold": threshold,
            **score_at_threshold(validation["label"], probabilities, threshold),
        }

    # Prefer recall at the FPR cap, then lower FPR and higher AP for ties.
    winner = min(comparisons, key=lambda name: (
        -comparisons[name]["recall"],
        comparisons[name]["false_positive_rate"],
        -comparisons[name]["average_precision"],
        name,
    ))
    return {"selected_model": winner, "candidates": comparisons}


def evaluate_test(task, candidates, rows, locked, seed):
    _, column = TASKS[task]
    results = {}
    for name, candidate in candidates.items():
        threshold = locked["candidates"][name]["threshold"]
        metrics = score_at_threshold(rows["label"], candidate.score(rows[column]), threshold)

        def predict_one(raw_value):
            value = normalize_url(raw_value)[0] if task == "url" else str(raw_value).strip()
            return candidate.score([value])[0] >= threshold

        metrics["inference_latency"] = measure_inference_latency(
            predict_one, rows["raw_input"], seed=seed
        )
        results[name] = {"threshold": threshold, **metrics}
    return results


def command_for(data_dir, stage3a_dir, output_dir):
    def quoted(path):
        return "'" + str(path).replace("'", "''") + "'"

    return (
        "& .\\venv\\Scripts\\python.exe .\\evaluate_stage3b.py"
        f" --data-dir {quoted(data_dir)} --stage3a-dir {quoted(stage3a_dir)}"
        f" --output-dir {quoted(output_dir)}"
    )


def render_markdown(report):
    lines = [
        "# Stage 3B offline comparison",
        "",
        f"The run reused the verified Stage 3A assignments with seed {report['split_audit']['seed']}. "
        "Dataset hashes and pairwise overlap checks passed before fitting. Both model selections and "
        "all thresholds were locked on validation before the held-out test evaluation.",
        "",
        "The logistic baselines reuse the Stage 3A refits. The linear SVMs use sigmoid calibration "
        "on out-of-fold training margins from three group-disjoint folds, each with its own fitted "
        "preprocessing.",
        "",
        f"Validation maximized recall at or below a {report['target_false_positive_rate']:.0%} "
        "false-positive rate. Candidate ties favor lower FPR and then higher average precision. "
        "The held-out test uses the same thresholds. Confusion matrices use "
        "`[[TN, FP], [FN, TP]]`. Latency is warm single-row app preprocessing, feature extraction, "
        "probability scoring, and classification on a seeded sample of up to 256 test rows, in milliseconds. "
        "Model loading and I/O take place outside the timed calls.",
        "",
    ]
    for task, (title, _) in TASKS.items():
        locked = report["validation_selection"][task]
        winner = locked["selected_model"]
        lines += [
            f"## {title}", "",
            f"Validation selected **{MODEL_NAMES[winner]}**.", "",
            "| Validation candidate | Recall | Actual FPR | Average precision | Threshold |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
        for name, val in locked["candidates"].items():
            lines.append(
                f"| {MODEL_NAMES[name]} | {val['recall']:.2%} | {val['false_positive_rate']:.4%} "
                f"| {val['average_precision']:.2%} | `{val['threshold']!r}` |"
            )
        lines += [
            "", "| Held-out candidate | Precision | Recall | F1 | AP | Actual FPR | Brier | "
            "Confusion matrix | Latency p50 / p95 (ms) |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |",
        ]
        for name, test in report["held_out_test"][task].items():
            latency = test["inference_latency"]
            lines.append(
                f"| {MODEL_NAMES[name]} | {test['precision']:.2%} | {test['recall']:.2%} "
                f"| {test['f1']:.2%} | {test['average_precision']:.2%} "
                f"| {test['false_positive_rate']:.4%} | {test['brier_score']:.4f} "
                f"| `{test['confusion_matrix']}` | {latency['median_ms']:.3f} / {latency['p95_ms']:.3f} |"
            )
        lines.append("")

    ablation = report["url_character_tfidf_ablation"]
    excluded = report["split_audit"]["url"]["excluded_rows"]
    labels = ", ".join(f"{count:,} {label}" for label, count in excluded["label_counts"].items())
    lines += [
        "## URL ablation and coverage", "",
        "The URL hybrid and lexical logistic regressions use the same model family and lexical "
        "features. Adding character TF-IDF changed recall under the validation FPR cap by "
        f"{100 * ablation['validation_recall_difference']:+.2f} percentage points. The held-out recall "
        f"difference at the two locked thresholds was {100 * ablation['test_recall_difference']:+.2f} points.",
        "",
        f"URL input validation excluded {excluded['total']:,} source rows ({labels}). "
        "These rows are listed in the verified Stage 3A exclusion manifest.",
        "", "## Reproduce", "", "```powershell", report["reproduction_command"],
        "& .\\venv\\Scripts\\python.exe -m pytest -q", "```", "",
    ]
    return "\n".join(lines)


def run(data_dir, stage3a_dir, output_dir):
    print("Verifying Stage 3A dataset hashes, assignments, and split overlap", flush=True)
    rows_by_task, audit = load_verified_stage3a(data_dir, stage3a_dir)
    seed = audit["seed"]
    reference = json.loads((stage3a_dir / "report.json").read_text(encoding="utf-8"))
    baseline_artifacts = {
        task: file_digest(stage3a_dir / filename) for task, filename in BASELINE_FILES.items()
    }
    print("Both Stage 3A datasets and split manifests verified", flush=True)

    selection, candidates, fitting = {}, {}, {}
    with threadpool_limits(limits=MODEL_THREADS):
        for task, (title, column) in TASKS.items():
            rows = rows_by_task[task]
            print(f"Fitting {title} candidates", flush=True)
            candidates[task], fitting[task] = fit_candidates(
                task, rows.loc[rows["split"] == "train"], stage3a_dir, seed
            )
            selection[task] = validate_candidates(
                candidates[task], rows.loc[rows["split"] == "validation"], column, reference[task]["validation"],
            )
            fitting[task]["logistic_stage3a_validation_reproduced"] = True
            winner = selection[task]["selected_model"]
            print(f"Validation selected {MODEL_NAMES[winner]} for {title}", flush=True)

        output_dir.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=output_dir, prefix=".pending-") as directory:
            pending = Path(directory)
            write_json(pending / "locked_selection.json", {
                "seed": seed,
                "target_false_positive_rate": TARGET_FPR,
                "stage3a_report": audit["stage3a_report"],
                "baseline_artifacts": baseline_artifacts,
                "validation_selection": selection,
            })
            print("Locked all choices and thresholds. Evaluating the held-out test splits", flush=True)
            test = {
                task: evaluate_test(task, candidates[task], rows.loc[rows["split"] == "test"], selection[task], seed)
                for task, rows in rows_by_task.items()
            }
            validation_url = selection["url"]["candidates"]
            test_url = test["url"]
            report = {
                "target_false_positive_rate": TARGET_FPR,
                "split_audit": audit,
                "baseline_artifacts": baseline_artifacts,
                "fitting": fitting,
                "environment": {
                    "platform": platform(), "logical_cpus": os.cpu_count(), "model_threads": MODEL_THREADS,
                    "python": python_version(),
                    "versions": {package: version(package) for package in (
                        "scikit-learn", "numpy", "scipy", "pandas", "joblib", "tldextract", "threadpoolctl",
                    )},
                },
                "validation_selection": selection,
                "held_out_test": test,
                "url_character_tfidf_ablation": {
                    "validation_recall_difference": (
                        validation_url["logistic"]["recall"] - validation_url["lexical_logistic"]["recall"]
                    ),
                    "test_recall_difference": test_url["logistic"]["recall"] - test_url["lexical_logistic"]["recall"],
                },
                "reproduction_command": command_for(data_dir, stage3a_dir, output_dir),
            }
            write_json(pending / "comparison.json", report)
            (pending / "comparison.md").write_text(render_markdown(report), encoding="utf-8")
            published = pending.rename(output_dir / pending.name.replace(".pending-", "run-", 1))
    print(f"Comparison report {published / 'comparison.md'}", flush=True)
    return published


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--stage3a-dir", type=Path, default=Path("data/stage3a/run-seed42"))
    parser.add_argument("--output-dir", type=Path, default=Path("data/stage3b"))
    args = parser.parse_args()
    try:
        run(args.data_dir, args.stage3a_dir, args.output_dir)
    except (FileNotFoundError, ValueError) as error:
        parser.exit(1, f"Stage 3B failed: {error}\n")


if __name__ == "__main__":
    main()
