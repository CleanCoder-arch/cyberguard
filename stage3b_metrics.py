"""Validation operating points and held-out metrics for Stage 3B."""

from time import perf_counter_ns

import numpy as np
from sklearn.metrics import brier_score_loss, roc_curve

from evaluate_url_domain_split import binary_metrics


def _binary_inputs(labels, probabilities):
    labels = np.asarray(labels)
    probabilities = np.asarray(probabilities, dtype=float)
    if labels.ndim != 1 or labels.shape != probabilities.shape:
        raise ValueError("Labels and probabilities must be one-dimensional and aligned.")
    if set(np.unique(labels)) != {0, 1}:
        raise ValueError("Metrics require both binary classes, labelled 0 and 1.")
    if not (np.isfinite(probabilities) & (probabilities >= 0) & (probabilities <= 1)).all():
        raise ValueError("Probabilities must be finite and in [0, 1].")
    return labels, probabilities


def threshold_for_fpr(labels, probabilities, target_fpr=0.01):
    """Maximize recall within the empirical FPR cap, preferring the highest cutoff on ties."""
    labels, probabilities = _binary_inputs(labels, probabilities)
    if not 0 <= target_fpr <= 1:
        raise ValueError("The false-positive rate cap must be in [0, 1].")

    false_positive_rates, recalls, thresholds = roc_curve(
        labels, probabilities, drop_intermediate=False
    )
    eligible = np.flatnonzero(false_positive_rates <= target_fpr)
    cutoff = thresholds[eligible[np.argmax(recalls[eligible])]]
    if np.isinf(cutoff):
        cutoff = np.nextafter(1.0, np.inf)
    return float(cutoff)


def score_at_threshold(labels, probabilities, threshold):
    """Score predictions from a fixed cutoff and calibration from the probabilities."""
    labels, probabilities = _binary_inputs(labels, probabilities)
    if not np.isfinite(threshold):
        raise ValueError("The decision threshold must be finite.")
    metrics = binary_metrics(labels, probabilities >= threshold, probabilities)
    true_negatives, false_positives = metrics["confusion_matrix"][0]
    return {
        **metrics,
        "false_positive_rate": false_positives / (true_negatives + false_positives),
        "brier_score": float(brier_score_loss(labels, probabilities, pos_label=1)),
    }


def measure_inference_latency(predict_one, inputs, *, seed, max_rows=256, warmups=10):
    """Time single-input scoring on a seeded held-out sample with models already loaded."""
    values = list(inputs)
    if not values or max_rows < 1 or warmups < 0:
        raise ValueError("Latency measurement requires inputs, a positive sample size, and nonnegative warmups.")
    indices = np.random.default_rng(seed).choice(
        len(values), size=min(max_rows, len(values)), replace=False
    )
    sample = [values[index] for index in indices]
    warmup_rows = min(warmups, len(sample))
    for value in sample[:warmup_rows]:
        predict_one(value)

    elapsed_ms = []
    for value in sample:
        start = perf_counter_ns()
        predict_one(value)
        elapsed_ms.append((perf_counter_ns() - start) / 1_000_000)
    return {
        "median_ms": float(np.median(elapsed_ms)),
        "p95_ms": float(np.percentile(elapsed_ms, 95)),
        "sample_rows": len(sample),
        "warmup_rows": warmup_rows,
    }
