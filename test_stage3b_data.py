import csv
import json

import pandas as pd
import pytest

from evaluate_stage3a import benchmark_summary, file_digest
from stage3a_sms import SMS_GROUPING, load_sms
from stage3a_url import URL_GROUPING, load_urls
from stage3b_data import load_verified_stage3a


@pytest.fixture
def stage3a_inputs(tmp_path):
    urls = tmp_path / "raw_urls.csv"
    sms = tmp_path / "raw_sms.csv"
    with urls.open("w", encoding="utf-8", newline="") as file:
        csv.writer(file).writerows([
            ("URL", "Label"),
            (" alpha.example.com/one ", "good"),
            ("beta.example.com/two", "bad"),
            ("broken host.test", "good"),
            ("alpha.example.net", "good"),
            ("beta.example.net", "bad"),
            ("http://broken host.test", "bad"),
            ("alpha.example.org", "good"),
            ("beta.example.org", "bad"),
        ])
    with sms.open("w", encoding="latin-1", newline="") as file:
        csv.writer(file).writerows([
            ("v1", "v2"),
            ("ham", "  Café\nmeet  "),
            ("spam", "Prize offer"),
            ("ham", "Are you home"),
            ("spam", "Claim your rate"),
            ("ham", "Tomorrow is fine"),
            ("spam", "Win orders now"),
        ])

    run = tmp_path / "stage3a"
    run.mkdir()
    report = {"seed": 42}
    for name, path, loader, keys, labels, grouping in (
        ("url", urls, load_urls, ["group_id", "hostname", "duplicate_key"], ["good", "bad"], URL_GROUPING),
        ("sms", sms, load_sms, ["group_id", "duplicate_key"], ["ham", "spam"], SMS_GROUPING),
    ):
        rows, excluded = loader(path)
        rows["split"] = ["train", "train", "validation", "validation", "test", "test"]
        rows[["row_id", "label", "split", *keys]].to_csv(run / f"{name}_assignments.csv", index=False)
        excluded.to_csv(run / f"{name}_excluded.csv", index=False)
        report[name] = {"dataset": file_digest(path), **benchmark_summary(rows, excluded, labels, keys, grouping)}
    (run / "report.json").write_text(json.dumps(report), encoding="utf-8")
    return tmp_path, run


def test_verified_inputs_preserve_manifest_splits_and_raw_text(stage3a_inputs):
    rows, audit = load_verified_stage3a(*stage3a_inputs)
    assert audit["seed"] == 42
    assert audit["url"]["excluded_rows"]["label_counts"] == {"good": 1, "bad": 1}
    assert rows["url"]["row_id"].tolist() == [1, 2, 4, 5, 7, 8]
    assert rows["url"].loc[0, "raw_input"] == " alpha.example.com/one "
    assert rows["sms"].loc[0, "raw_input"] == "  Café\nmeet  "
    assert rows["sms"].loc[0, "text"] == "Café\nmeet"
    assert rows["url"].loc[2, "split"] == "validation"


def test_stage3b_rejects_changed_raw_bytes(stage3a_inputs):
    data, _ = stage3a_inputs
    with (data / "raw_sms.csv").open("ab") as file:
        file.write(b"\n")
    with pytest.raises(ValueError, match="Dataset SHA-256 for raw_sms.csv"):
        load_verified_stage3a(*stage3a_inputs)


def test_stage3b_rechecks_group_overlap_in_saved_assignments(stage3a_inputs):
    _, run = stage3a_inputs
    path = run / "url_assignments.csv"
    rows = pd.read_csv(path)
    rows.loc[0, "split"] = "validation"
    rows.to_csv(path, index=False)
    with pytest.raises(ValueError, match="Cross-split overlap for group_id"):
        load_verified_stage3a(*stage3a_inputs)
