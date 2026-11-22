"""Build and evaluate the Stage 3A baselines on grouped benchmark splits."""

import argparse
import json
from hashlib import sha256
from importlib.metadata import version
from itertools import combinations
from pathlib import Path
from platform import python_version
from tempfile import TemporaryDirectory

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from threadpoolctl import threadpool_limits

from evaluate_url_domain_split import (
    binary_metrics, evaluate_legacy, fit_url_baseline, transform_urls,
)
from stage3a_sms import SMS_GROUPING, load_sms
from stage3a_url import URL_GROUPING, load_urls


SPLIT_FRACTIONS = {"train": 0.70, "validation": 0.15, "test": 0.15}
DEFAULT_SEED = 42
DASHBOARD_RESULTS = {
    "url": {"accuracy": 0.9368, "precision": 0.9403, "recall": 0.9303, "f1": 0.9353},
    "sms": {"accuracy": 0.9845, "precision": 0.9675, "recall": 0.9084, "f1": 0.9370},
}


def split_groups(rows, seed):
    """Assign whole groups while targeting the requested share of each label."""
    counts = rows.groupby(["group_id", "label"]).size().unstack(fill_value=0)
    counts = counts.reindex(columns=[0, 1], fill_value=0)
    if (counts.gt(0).sum() < len(SPLIT_FRACTIONS)).any():
        raise ValueError("Each class must occur in at least three groups to build three splits.")

    # Prioritize large or class-heavy groups. Seeded order breaks ties among groups.
    totals = counts.sum()
    weights = (counts / totals).sample(frac=1, random_state=seed)
    order = weights.sum(axis=1).sort_values(ascending=False, kind="stable").index
    # Start with an empty allocation and choose the smallest increase in weighted
    # squared error from the per-class targets. The common term cancels across splits.
    assigned = {split: [0.0, 0.0] for split in SPLIT_FRACTIONS}
    groups = {}
    for group, negative, positive in weights.loc[order].itertuples(name=None):
        split = min(
            SPLIT_FRACTIONS,
            key=lambda name: (
                negative * (2 * assigned[name][0] + negative)
                + positive * (2 * assigned[name][1] + positive)
            ) / SPLIT_FRACTIONS[name],
        )
        groups[group] = split
        assigned[split][0] += negative
        assigned[split][1] += positive

    # With very few groups of one class, the balance objective can leave a split
    # without that class. Move a group from a split that can spare both its labels.
    presence = counts.gt(0)
    coverage = presence.groupby(groups).sum().reindex(SPLIT_FRACTIONS, fill_value=0)
    for name in SPLIT_FRACTIONS:
        for label in (0, 1):
            if coverage.at[name, label]:
                continue
            for group in reversed(order):
                donor = groups[group]
                has_label = presence.loc[group]
                if has_label[label] and (coverage.loc[donor] > has_label).loc[has_label].all():
                    groups[group] = name
                    coverage.loc[donor] -= has_label.astype(int)
                    coverage.loc[name] += has_label.astype(int)
                    break

    return rows.assign(split=rows["group_id"].map(groups))


def check_split_overlap(rows, keys):
    """Return pairwise overlap counts and reject any shared key across splits."""
    by_split = {name: frame for name, frame in rows.groupby("split")}
    checks = {}
    for key in keys:
        if rows[key].isna().any():
            raise ValueError(f"Missing values in split audit key {key}.")
        values = {name: set(by_split[name][key]) for name in SPLIT_FRACTIONS}
        checks[key] = {
            f"{left}/{right}": len(values[left] & values[right])
            for left, right in combinations(SPLIT_FRACTIONS, 2)
        }
        if any(checks[key].values()):
            raise ValueError(f"Cross-split overlap for {key}: {checks[key]}")
    return checks


def benchmark_summary(rows, excluded, labels, keys, grouping):
    return {
        "labels": labels,
        "grouping": grouping,
        "input_rows": len(rows) + len(excluded),
        "excluded_rows_by_reason": excluded["reason"].value_counts().to_dict(),
        "splits": {
            name: {
                "rows": len(frame),
                "groups": frame["group_id"].nunique(),
                "class_counts": {
                    label: int(frame["label"].eq(code).sum())
                    for code, label in enumerate(labels)
                },
            }
            for name, frame in rows.groupby("split", sort=False)
        },
        "pairwise_overlap": check_split_overlap(rows, keys),
    }


def train_sms_baseline(train, validation, seed):
    model = make_pipeline(
        TfidfVectorizer(
            lowercase=True,
            strip_accents="unicode",
            ngram_range=(1, 2),
            min_df=2,
            max_features=30000,
            sublinear_tf=True,
        ),
        LogisticRegression(max_iter=2000, class_weight="balanced", C=3.0, random_state=seed),
    )
    model.fit(train["text"], train["label"])
    messages = validation["text"]
    metrics = binary_metrics(
        validation["label"], model.predict(messages), model.predict_proba(messages)[:, 1]
    )
    return model, metrics


def train_url_baseline(train, validation, seed):
    model, vectorizer, scaler = fit_url_baseline(train["url"], train["label"], seed)
    features = transform_urls(validation["url"], vectorizer, scaler)
    metrics = binary_metrics(
        validation["label"], model.predict(features), model.predict_proba(features)[:, 1]
    )
    return {"model": model, "vectorizer": vectorizer, "scaler": scaler}, metrics


def file_digest(path):
    digest = sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return {"file": path.name, "sha256": digest.hexdigest()}


def write_json(path, contents):
    path.write_text(json.dumps(contents, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def publish_run(output_dir, benchmarks, models, historical, report):
    """Publish the whole run together, with each run in its own directory."""
    output_dir.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=output_dir, prefix=".pending-") as directory:
        pending = Path(directory)
        for name, rows, excluded, keys in benchmarks:
            rows[["row_id", "label", "split", *keys]].to_csv(
                pending / f"{name}_assignments.csv", index=False
            )
            excluded.to_csv(pending / f"{name}_excluded.csv", index=False)
        for name, model in models.items():
            joblib.dump(model, pending / name)
        write_json(pending / "historical.json", historical)
        write_json(pending / "report.json", report)
        return pending.rename(output_dir / pending.name.replace(".pending-", "run-", 1))


def run(data_dir, output_dir, seed):
    url_path = data_dir / "raw_urls.csv"
    sms_path = data_dir / "raw_sms.csv"
    legacy_path = data_dir / "urls.csv"
    hashes = {path.name: file_digest(path) for path in (url_path, sms_path)}

    print("Reproducing the historical URL hostname split", flush=True)
    legacy = evaluate_legacy(legacy_path)

    print("Validating and grouping raw URLs and SMS messages", flush=True)
    urls, excluded_urls = load_urls(url_path)
    sms, excluded_sms = load_sms(sms_path)
    urls = split_groups(urls, seed)
    sms = split_groups(sms, seed)
    url_keys = ["group_id", "hostname", "duplicate_key"]
    sms_keys = ["group_id", "duplicate_key"]

    report = {
        "seed": seed,
        "target_split_fractions": SPLIT_FRACTIONS,
        "split_method": "seeded group allocation targeting class counts",
        "evaluated_split": "validation",
        "reserved_split": "test",
        "versions": {"python": python_version(), **{
            package: version(package) for package in
            ("pandas", "numpy", "scipy", "scikit-learn", "tldextract", "joblib", "threadpoolctl")
        }},
        "url": {
            "benchmark": "URL maliciousness detection",
            "dataset": hashes[url_path.name],
            **benchmark_summary(urls, excluded_urls, ["good", "bad"], url_keys, URL_GROUPING),
        },
        "sms": {
            "benchmark": "SMS spam detection",
            "dataset": hashes[sms_path.name],
            **benchmark_summary(sms, excluded_sms, ["ham", "spam"], sms_keys, SMS_GROUPING),
        },
    }

    print("Fitting the SMS spam detection baseline", flush=True)
    with threadpool_limits(limits=1):
        sms_model, report["sms"]["validation"] = train_sms_baseline(
            sms[sms["split"] == "train"], sms[sms["split"] == "validation"], seed
        )
        print("Fitting the hybrid URL baseline", flush=True)
        url_model, report["url"]["validation"] = train_url_baseline(
            urls[urls["split"] == "train"], urls[urls["split"] == "validation"], seed
        )

    historical = {
        "dashboard_reported": DASHBOARD_RESULTS,
        "url_hostname_split_rerun": legacy,
        "provenance": (
            "The URL rerun fits a fresh historical-protocol model. The shipped models may "
            "have already seen rows in the Stage 3A datasets. Only Stage 3A refits were "
            "scored on the Stage 3A validation splits."
        ),
    }

    benchmarks = (
        ("url", urls, excluded_urls, url_keys),
        ("sms", sms, excluded_sms, sms_keys),
    )
    models = {"url_hybrid_baseline.joblib": url_model, "sms_baseline.joblib": sms_model}
    run_dir = publish_run(output_dir, benchmarks, models, historical, report)

    for name in ("url", "sms"):
        summary = report[name]
        print(summary["benchmark"], json.dumps(summary["validation"]))
        print("Overlap counts", json.dumps(summary["pairwise_overlap"]))
        print("Excluded rows by reason", json.dumps(summary["excluded_rows_by_reason"]))
    print(f"Historical URL F1 {legacy['metrics']['f1']:.2%}")
    print(f"Output directory {run_dir}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("data"),
                        help="Directory containing raw_urls.csv, raw_sms.csv and urls.csv.")
    parser.add_argument("--output-dir", type=Path, default=Path("data/stage3a"),
                        help="Parent directory for completed runs.")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()
    if not 0 <= args.seed <= np.iinfo(np.uint32).max:
        parser.error("--seed must be between 0 and 4294967295")
    try:
        run(args.data_dir, args.output_dir, args.seed)
    except (FileNotFoundError, ValueError) as error:
        parser.exit(1, f"Stage 3A failed: {error}\n")


if __name__ == "__main__":
    main()
