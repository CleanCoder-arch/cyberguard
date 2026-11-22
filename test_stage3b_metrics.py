import json

import numpy as np
import pandas as pd
import pytest

import stage3b_metrics
from stage3b_metrics import measure_inference_latency, score_at_threshold, threshold_for_fpr


def test_threshold_enforces_seven_false_positives_and_keeps_tied_scores_together():
    labels = np.array([0] * 724 + [1] * 4)
    probabilities = np.array([0.99] * 7 + [0.85] * 2 + [0.2] * 715 + [0.92, 0.91, 0.90, 0.85])
    cutoff = threshold_for_fpr(labels, probabilities)
    result = score_at_threshold(labels, probabilities, cutoff)

    assert cutoff == 0.90
    assert result["confusion_matrix"] == [[717, 7], [1, 3]]
    assert result["recall"] == 0.75
    assert result["false_positive_rate"] == pytest.approx(7 / 724)
    assert result["brier_score"] == pytest.approx(np.mean((probabilities - labels) ** 2))


def test_threshold_prefers_the_higher_cutoff_when_recall_ties():
    labels = [0] * 724 + [1] * 2
    probabilities = [0.8] * 7 + [0.2] * 717 + [0.9, 0.95]

    assert threshold_for_fpr(labels, probabilities) == 0.9


def test_threshold_for_all_negative_decisions_is_finite_and_round_trips():
    labels, probabilities = [0, 0, 1], [0.9, 0.2, 0.9]
    cutoff = threshold_for_fpr(labels, probabilities)

    assert cutoff == np.nextafter(1.0, np.inf)
    assert json.loads(json.dumps(cutoff, allow_nan=False)) == cutoff
    assert score_at_threshold(labels, probabilities, cutoff)["confusion_matrix"] == [[2, 0], [1, 0]]


def test_latency_samples_positionally_and_warms_up_before_timing(monkeypatch):
    inputs = pd.Series(["four", "five", "six", "seven"], index=[4, 5, 6, 7])
    visits = []
    ticks = iter([0, 1_000_000, 1_000_000, 3_000_000, 3_000_000, 6_000_000])
    monkeypatch.setattr(stage3b_metrics, "perf_counter_ns", lambda: next(ticks))

    result = measure_inference_latency(visits.append, inputs, seed=42, max_rows=3, warmups=2)

    assert visits[:2] == visits[2:4]
    assert len(set(visits[2:])) == 3
    assert result == {"median_ms": 2.0, "p95_ms": 2.9, "sample_rows": 3, "warmup_rows": 2}
