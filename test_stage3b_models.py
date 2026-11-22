import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

from evaluate_stage3a import train_sms_baseline
from stage3b_models import fit_candidates, group_folds


def test_sms_calibration_fits_tfidf_inside_group_disjoint_training_folds(tmp_path, monkeypatch):
    train = pd.DataFrame(
        [
            (f"{word} group{label}{number} {suffix}", label, f"{label}-{number}", "train")
            for label, word in enumerate(("hello", "offer"))
            for number in range(9)
            for suffix in ("message", "text")
        ],
        columns=["text", "label", "group_id", "split"],
    )
    baseline, _ = train_sms_baseline(train, train, seed=42)
    joblib.dump(baseline, tmp_path / "sms_baseline.joblib")

    fit_transform = TfidfVectorizer.fit_transform
    fitted_documents = []

    def record_fit(vectorizer, documents, y=None):
        fitted_documents.append(list(documents))
        return fit_transform(vectorizer, documents, y)

    monkeypatch.setattr(TfidfVectorizer, "fit_transform", record_fit)
    models, audit = fit_candidates("sms", train, tmp_path, seed=42)

    folds = list(group_folds(train["label"].to_numpy(), train["group_id"].to_numpy(), seed=42))
    assert fitted_documents == [train["text"].iloc[fit].tolist() for fit, _ in folds]
    np.testing.assert_array_equal(np.sort(np.concatenate([out for _, out in folds])), train.index)
    for fit, held_out in folds:
        assert set(train["group_id"].iloc[fit]).isdisjoint(train["group_id"].iloc[held_out])
    assert all(fold["group_overlap"] == 0 for fold in audit["folds"])
    scores = models["linear_svm_calibrated"].score(train["text"])
    assert scores.shape == (len(train),)
    assert np.all((0 <= scores) & (scores <= 1))
