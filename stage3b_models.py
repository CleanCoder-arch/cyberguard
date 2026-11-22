"""Fit Stage 3B candidates using the verified Stage 3A training rows."""

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.base import clone
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC
from sklearn.utils.validation import check_is_fitted

from evaluate_url_domain_split import URL_FEATURE_COLUMNS, _handcrafted_rows


FOLDS = 3


def _features(values, lexical, vectorizer, scaler):
    if lexical is None:
        return values if vectorizer is None else vectorizer.transform(values)
    dense = lexical if scaler is None else scaler.transform(lexical)
    if vectorizer is None:
        return dense
    return hstack([vectorizer.transform(values), csr_matrix(dense)], format="csr")


@dataclass(frozen=True)
class Candidate:
    model: object
    vectorizer: TfidfVectorizer | None = None
    scaler: StandardScaler | None = None
    uses_lexical: bool = False
    calibrator: LogisticRegression | None = None

    def score(self, values):
        """Score app-preprocessed URLs or SMS texts with the fitted pipeline."""
        lexical = _handcrafted_rows(values) if self.uses_lexical else None
        features = _features(values, lexical, self.vectorizer, self.scaler)
        if self.calibrator is not None:
            margins = self.model.decision_function(features).reshape(-1, 1)
            return self.calibrator.predict_proba(margins)[:, 1]
        return self.model.predict_proba(features)[:, 1]


def _load_baseline(task, stage3a_dir, train_size):
    stage3a_dir = Path(stage3a_dir)
    if task == "sms":
        artifact = joblib.load(stage3a_dir / "sms_baseline.joblib")
        model = artifact.named_steps["logisticregression"]
        vectorizer = artifact.named_steps["tfidfvectorizer"]
        scaler = None
    else:
        artifact = joblib.load(stage3a_dir / "url_hybrid_baseline.joblib")
        model, vectorizer, scaler = (artifact[key] for key in ("model", "vectorizer", "scaler"))
        if not isinstance(scaler, StandardScaler):
            raise ValueError("Stage 3A URL preprocessing must use a StandardScaler.")
        check_is_fitted(scaler)
        if tuple(scaler.feature_names_in_) != URL_FEATURE_COLUMNS or scaler.n_samples_seen_ != train_size:
            raise ValueError("Stage 3A URL scaler does not match the training split and feature schema.")

    if not isinstance(model, LogisticRegression) or not isinstance(vectorizer, TfidfVectorizer):
        raise ValueError(f"Stage 3A {task} artifacts must contain logistic regression and TF-IDF.")
    check_is_fitted(model)
    check_is_fitted(vectorizer)
    lexical_width = len(URL_FEATURE_COLUMNS) if task == "url" else 0
    if (model.classes_.tolist() != [0, 1]
            or model.n_features_in_ != len(vectorizer.vocabulary_) + lexical_width
            or len(vectorizer.idf_) != len(vectorizer.vocabulary_)):
        raise ValueError(f"Stage 3A {task} baseline does not match its fitted feature schema.")
    return Candidate(model, vectorizer, scaler, uses_lexical=task == "url")


def group_folds(labels, groups, seed):
    """Yield deterministic stratified folds, each disjoint by original group."""
    unique_groups, codes = np.unique(groups, return_inverse=True)
    # Seed the group ordering while preserving the association between groups and
    # their class counts inside StratifiedGroupKFold.
    ordered_codes = np.random.default_rng(seed).permutation(len(unique_groups))[codes]
    splitter = StratifiedGroupKFold(n_splits=FOLDS)
    for fit, held_out in splitter.split(labels, labels, ordered_codes):
        overlap = np.intersect1d(ordered_codes[fit], ordered_codes[held_out]).size
        if overlap or np.unique(labels[fit]).size != 2 or np.unique(labels[held_out]).size != 2:
            raise ValueError("Calibration fold has shared groups or is missing a class.")
        yield fit, held_out


def _fold_counts(labels, groups, indices):
    counts = np.bincount(labels[indices], minlength=2)
    return {
        "rows": int(len(indices)),
        "groups": int(np.unique(groups[indices]).size),
        "class_counts": {"0": int(counts[0]), "1": int(counts[1])},
    }


def _fit_status(estimator):
    iterations = int(np.max(estimator.n_iter_))
    return {"iterations": iterations, "converged": iterations < estimator.max_iter}


def _fit_calibrated_svm(task, values, labels, groups, lexical, baseline, seed):
    svm = LinearSVC(
        C=1.0, dual=task == "sms", class_weight="balanced" if task == "sms" else None,
        tol=1e-3, max_iter=2000, random_state=seed,
    )
    margins = np.full(len(values), np.nan)
    audit = []
    for fold, (fit, held_out) in enumerate(group_folds(labels, groups, seed), start=1):
        print(f"{task.upper()} calibration fold {fold}/{FOLDS}", flush=True)
        vectorizer = clone(baseline.vectorizer)
        train_features = vectorizer.fit_transform(values[fit])
        scaler = None
        if lexical is not None:
            scaler = StandardScaler()
            scaled = scaler.fit_transform(lexical.iloc[fit])
            train_features = hstack([train_features, csr_matrix(scaled)], format="csr")
            del scaled
        fold_model = clone(svm).fit(train_features, labels[fit])
        del train_features

        held_out_lexical = None if lexical is None else lexical.iloc[held_out]
        if np.isfinite(margins[held_out]).any():
            raise ValueError("A training row appears in multiple calibration holdouts.")
        margins[held_out] = fold_model.decision_function(
            _features(values[held_out], held_out_lexical, vectorizer, scaler)
        )
        audit.append({
            "fold": fold,
            "fit": _fold_counts(labels, groups, fit),
            "out_of_fold": _fold_counts(labels, groups, held_out),
            "group_overlap": 0,
            "svm_fit": _fit_status(fold_model),
        })
        del fold_model, vectorizer, scaler, held_out_lexical

    if not np.isfinite(margins).all():
        raise ValueError("Calibration requires a finite out-of-fold margin for every training row.")
    calibrator = LogisticRegression(penalty=None, max_iter=2000, random_state=seed)
    calibrator.fit(margins.reshape(-1, 1), labels)
    print(f"{task.upper()} full-training SVM fit", flush=True)
    svm.fit(_features(values, lexical, baseline.vectorizer, baseline.scaler), labels)
    return Candidate(svm, baseline.vectorizer, baseline.scaler, task == "url", calibrator), {
        "method": "sigmoid fitted on out-of-fold decision margins",
        "fold_splitter": "StratifiedGroupKFold with seeded group ordering",
        "fold_seed": seed,
        "folds": audit,
        "svm_parameters": svm.get_params(),
        "full_train_svm_fit": _fit_status(svm),
        "full_train_preprocessing": "reused Stage 3A training-only TF-IDF and URL scaler",
        "sigmoid_fit": {
            **_fit_status(calibrator),
            "slope": float(calibrator.coef_[0, 0]),
            "intercept": float(calibrator.intercept_[0]),
        },
    }


def fit_candidates(task, train, stage3a_dir, seed):
    """Fit candidates and return their scoring adapters and training audit."""
    if task not in {"sms", "url"} or set(train["split"]) != {"train"}:
        raise ValueError("Candidate fitting requires the SMS or URL training split.")

    values = train["url" if task == "url" else "text"].to_numpy()
    labels = train["label"].to_numpy()
    groups = train["group_id"].to_numpy()
    baseline = _load_baseline(task, stage3a_dir, len(train))
    # Feature extraction is stateless. Each calibration fold fits its own scaler.
    lexical = _handcrafted_rows(values) if task == "url" else None
    svm, audit = _fit_calibrated_svm(task, values, labels, groups, lexical, baseline, seed)
    candidates = {"logistic": baseline, "linear_svm_calibrated": svm}
    if lexical is not None:
        print("URL lexical-only logistic and tree fits", flush=True)
        lexical_logistic = clone(baseline.model).fit(baseline.scaler.transform(lexical), labels)
        tree = HistGradientBoostingClassifier(
            max_iter=100, max_leaf_nodes=31, early_stopping=False, random_state=seed,
        ).fit(lexical, labels)
        candidates.update({
            "lexical_logistic": Candidate(lexical_logistic, scaler=baseline.scaler, uses_lexical=True),
            "lexical_tree": Candidate(tree, uses_lexical=True),
        })
        audit["lexical_candidates"] = {
            "lexical_logistic": {"parameters": lexical_logistic.get_params(), **_fit_status(lexical_logistic)},
            "lexical_tree": {"parameters": tree.get_params(), "iterations": int(tree.n_iter_)},
        }
    return candidates, audit
