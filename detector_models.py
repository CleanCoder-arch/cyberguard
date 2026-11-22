from functools import lru_cache
from math import fsum
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


MODELS_DIR = Path(__file__).resolve().parent / "models"


class DetectorUnavailableError(RuntimeError):
    """Raised when a detector's model artifacts cannot be loaded."""


@lru_cache(maxsize=2)
def load_artifacts(detector, *paths):
    try:
        return tuple(joblib.load(path) for path in paths)
    except Exception as error:
        raise DetectorUnavailableError(
            f"The {detector} detector is unavailable because its model files could not be loaded."
        ) from error


@lru_cache(maxsize=2)
def _text_feature_names(vectorizer):
    return vectorizer.get_feature_names_out()


def explain_model(
    model, vectorizer, features, *, positive_class, text_kind, structure=None
):
    """Decompose one logistic regression score with optional raw structural values."""
    if (
        not isinstance(model, LogisticRegression)
        or not isinstance(vectorizer, TfidfVectorizer)
        or model.classes_.tolist() != [0, 1]
        or model.coef_.shape != (1, features.shape[1])
    ):
        return {"status": "unavailable"}

    text_names = _text_feature_names(vectorizer)
    text_count = len(text_names)
    structural_names = list(structure) if structure is not None else []
    if text_count + len(structural_names) != features.shape[1]:
        return {"status": "unavailable"}

    row = features.tocsr()
    weights = (model.coef_[0, row.indices] * row.data).tolist()
    contributions = list(zip(row.indices.tolist(), weights))
    positive = sorted(
        (item for item in contributions if item[1] > 0),
        key=lambda item: (-item[1], item[0]),
    )[:3]
    negative = sorted(
        (item for item in contributions if item[1] < 0),
        key=lambda item: (item[1], item[0]),
    )[:3]

    def describe(items):
        descriptions = []
        for index, contribution in items:
            is_text = index < text_count
            feature = str(text_names[index]) if is_text else structural_names[index - text_count]
            description = {
                "feature": feature,
                "kind": text_kind if is_text else "url_structure",
                "contribution": contribution,
            }
            if not is_text:
                description["value"] = float(structure[feature])
            descriptions.append(description)
        return descriptions

    baseline = float(model.intercept_[0])
    shown = {index for index, _ in positive + negative}
    return {
        "status": "completed",
        "scale": "log_odds",
        "positive_class": positive_class,
        "baseline": baseline,
        "total": fsum([baseline, *weights]),
        "other_contribution": fsum(
            weight for index, weight in contributions if index not in shown
        ),
        "positive": describe(positive),
        "negative": describe(negative),
    }
