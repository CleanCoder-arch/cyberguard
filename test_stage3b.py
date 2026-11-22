import json

import numpy as np
import pandas as pd

import evaluate_stage3b as benchmark
from evaluate_url_domain_split import binary_metrics


def test_all_model_choices_are_locked_before_held_out_scoring(tmp_path, monkeypatch):
    stage3a = tmp_path / "stage3a"
    stage3a.mkdir()
    output = tmp_path / "stage3b"
    reference = binary_metrics([0, 1], [0, 1], [0.2, 0.8])
    (stage3a / "report.json").write_text(json.dumps({
        task: {"validation": reference} for task in benchmark.TASKS
    }), encoding="utf-8")
    for filename in benchmark.BASELINE_FILES.values():
        (stage3a / filename).write_bytes(b"test artifact")

    rows = {}
    for task, (_, column) in benchmark.TASKS.items():
        inputs = [f"https://example.org/{split}/{label}" for split in ("train", "validation", "test")
                  for label in (0, 1)]
        rows[task] = pd.DataFrame({
            column: inputs, "raw_input": inputs,
            "split": ["train"] * 2 + ["validation"] * 2 + ["test"] * 2, "label": [0, 1] * 3,
        })
    audit = {"seed": 42, "stage3a_report": {}, "url": {"excluded_rows": {"total": 0, "label_counts": {}}}}
    monkeypatch.setattr(benchmark, "load_verified_stage3a", lambda *_: (rows, audit))

    class Candidate:
        def score(self, values):
            probabilities = []
            for value in values:
                split, label = value.split("/")[-2:]
                if split == "test":
                    lock, = output.glob(".pending-*/locked_selection.json")
                    locked = json.loads(lock.read_text(encoding="utf-8"))["validation_selection"]
                    assert set(locked) == {"sms", "url"}
                    assert all(entry["candidates"]["logistic"]["threshold"] == 0.8 for entry in locked.values())
                probabilities.append(0.2 if label == "0" else (0.7 if split == "test" else 0.8))
            return np.array(probabilities)

    def fit(task, train, *_):
        assert train["split"].tolist() == ["train", "train"]
        candidates = {"logistic": Candidate()}
        if task == "url":
            candidates["lexical_logistic"] = Candidate()
        return candidates, {}

    monkeypatch.setattr(benchmark, "fit_candidates", fit)
    published = benchmark.run(tmp_path, stage3a, output)
    report = json.loads((published / "comparison.json").read_text(encoding="utf-8"))
    for task in benchmark.TASKS:
        assert report["held_out_test"][task]["logistic"]["recall"] == 0.0
        assert report["held_out_test"][task]["logistic"]["threshold"] == 0.8
