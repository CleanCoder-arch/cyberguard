"""Verify and load the exact Stage 3A rows and assignments for Stage 3B."""

import csv
import io
import json
from pathlib import Path

import pandas as pd

from evaluate_stage3a import SPLIT_FRACTIONS, benchmark_summary, file_digest
from stage3a_sms import SMS_GROUPING, load_sms
from stage3a_url import URL_GROUPING, load_urls


def _read_manifest(path, dtypes):
    records = pd.read_csv(path, dtype=dtypes, keep_default_na=False, skip_blank_lines=False)
    if set(records) != set(dtypes) or records["row_id"].duplicated().any():
        raise ValueError(f"Invalid Stage 3A manifest schema or duplicate row IDs in {path.name}.")
    return records.sort_values("row_id", ignore_index=True)


def _verify_benchmark(path, stage3a_dir, name, saved, load_rows, audit_keys, labels, grouping):
    rows, excluded = load_rows(path)
    assignment_path = stage3a_dir / f"{name}_assignments.csv"
    assignment_dtypes = {"row_id": "int64", "label": "int64", "split": str}
    assignment_dtypes.update(dict.fromkeys(audit_keys, str))
    assignments = _read_manifest(assignment_path, assignment_dtypes)
    for column in ["row_id", "label", *audit_keys]:
        if not rows[column].equals(assignments[column]):
            raise ValueError(f"Stage 3A {name} assignments disagree with the source {column} values.")
    if set(assignments["split"]) != set(SPLIT_FRACTIONS):
        raise ValueError(f"Stage 3A {name} assignments have unexpected split names.")
    rows["split"] = assignments["split"]
    del assignments

    exclusion_path = stage3a_dir / f"{name}_excluded.csv"
    expected_excluded = _read_manifest(exclusion_path, {"row_id": "int64", "reason": str})
    if not excluded.astype({"row_id": "int64"}).equals(expected_excluded):
        raise ValueError(f"Stage 3A {name} exclusion manifest disagrees with source validation.")

    summary = benchmark_summary(rows, excluded, labels, audit_keys, grouping)
    for field, observed in summary.items():
        if observed != saved.get(field):
            raise ValueError(f"Stage 3A {name} report disagrees with verified {field}.")

    audit = {
        "dataset": saved["dataset"],
        "assignments": file_digest(assignment_path),
        "exclusions": file_digest(exclusion_path),
        "input_rows": summary["input_rows"],
        "splits": summary["splits"],
        "pairwise_overlap": summary["pairwise_overlap"],
        "excluded_rows": {"total": len(excluded), "reason_counts": summary["excluded_rows_by_reason"]},
    }
    return rows, excluded, audit


def _raw_sms_messages(path):
    raw = path.read_bytes()
    try:
        contents = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        contents = raw.decode("latin-1")
    reader = csv.reader(io.StringIO(contents, newline=""), strict=True)
    message_index = next(reader).index("v2")
    return pd.Series([fields[message_index] if len(fields) > message_index else "" for fields in reader])


def load_verified_stage3a(data_dir, stage3a_dir):
    """Validate both datasets and manifests before making any fitting inputs available."""
    data_dir, stage3a_dir = Path(data_dir), Path(stage3a_dir)
    report_path = stage3a_dir / "report.json"
    saved = json.loads(report_path.read_text(encoding="utf-8"))
    seed = saved.get("seed")
    if type(seed) is not int or not 0 <= seed <= 2**32 - 1:
        raise ValueError("Invalid seed in the Stage 3A report.")

    url_path = data_dir / "raw_urls.csv"
    sms_path = data_dir / "raw_sms.csv"
    for name, path in (("url", url_path), ("sms", sms_path)):
        if file_digest(path) != saved.get(name, {}).get("dataset"):
            raise ValueError(f"Dataset SHA-256 for {path.name} disagrees with the Stage 3A report.")

    urls, excluded_urls, url_audit = _verify_benchmark(
        url_path, stage3a_dir, "url", saved["url"], load_urls,
        ["group_id", "hostname", "duplicate_key"], ["good", "bad"], URL_GROUPING,
    )
    sms, _, sms_audit = _verify_benchmark(
        sms_path, stage3a_dir, "sms", saved["sms"], load_sms,
        ["group_id", "duplicate_key"], ["ham", "spam"], SMS_GROUPING,
    )

    # Use the same parsing options as Stage 3A to keep source record ordinals aligned.
    url_source = pd.read_csv(
        url_path, usecols=["URL", "Label"], dtype=str, keep_default_na=False, skip_blank_lines=False,
    )
    urls["raw_input"] = url_source["URL"].iloc[urls["row_id"] - 1].to_numpy()
    sms["raw_input"] = _raw_sms_messages(sms_path).iloc[sms["row_id"] - 1].to_numpy()

    excluded_labels = url_source["Label"].iloc[excluded_urls["row_id"].astype(int) - 1].str.strip()
    counts = {label: int(excluded_labels.eq(label).sum()) for label in ("good", "bad")}
    other = len(excluded_labels) - sum(counts.values())
    if other:
        counts["missing_or_unsupported"] = other
    url_audit["excluded_rows"]["label_counts"] = counts

    return {"url": urls, "sms": sms}, {
        "seed": seed, "stage3a_report": file_digest(report_path), "url": url_audit, "sms": sms_audit,
    }
