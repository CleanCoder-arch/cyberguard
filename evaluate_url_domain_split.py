import argparse
import hashlib
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler

from stage3a_url import registrable_group
from url_features import extract_features


DASHBOARD_URL_F1 = 0.9353
DEFAULT_LEGACY_DATA = Path("data") / "urls.csv"
URL_FEATURE_COLUMNS = tuple(extract_features(""))
DIAGNOSTIC_URLS = (
    "https://google.com",
    "https://github.com",
    "https://www.microsoft.com",
    "https://www.amazon.com",
    "https://www.wikipedia.org",
    "https://www.youtube.com",
    "http://secure-login-bank.xyz/verify",
    "http://paypal-login-security.xyz/login",
    "http://secure-account-verification.xyz/login",
)


def get_hostname(url):
    """Reproduce the historical exact-host grouping, including its fallback."""
    value = str(url).strip()
    if not value.startswith(("http://", "https://")):
        value = "http://" + value
    try:
        hostname = urlparse(value).hostname
    except ValueError:
        return "invalid-host"
    return hostname.lower() if hostname else "invalid-host"


def _handcrafted_rows(urls):
    values = np.empty((len(urls), len(URL_FEATURE_COLUMNS)), dtype=float, order="F")
    for index, url in enumerate(urls):
        features = extract_features(url)
        values[index] = [features[column] for column in URL_FEATURE_COLUMNS]
    return pd.DataFrame(values, columns=URL_FEATURE_COLUMNS)


def fit_url_baseline(urls, labels, seed):
    """Fit the hybrid baseline and both preprocessing artifacts on training rows."""
    urls = list(urls)
    vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=(2, 5),
        min_df=2,
        max_features=50000,
        sublinear_tf=True,
    )
    tfidf = vectorizer.fit_transform(urls)
    scaler = StandardScaler()
    scaled = scaler.fit_transform(_handcrafted_rows(urls))
    model = LogisticRegression(max_iter=2000, C=5.0, random_state=seed)
    model.fit(hstack([tfidf, csr_matrix(scaled)], format="csr"), labels)
    return model, vectorizer, scaler


def transform_urls(urls, vectorizer, scaler):
    """Build hybrid features from URLs preprocessed by the caller."""
    urls = list(urls)
    tfidf = vectorizer.transform(urls)
    scaled = scaler.transform(_handcrafted_rows(urls))
    return hstack([tfidf, csr_matrix(scaled)], format="csr")


def binary_metrics(labels, predictions, probabilities):
    """Score positive label 1 using predictions and positive-class probabilities."""
    return {
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "average_precision": float(average_precision_score(labels, probabilities)),
        "confusion_matrix": confusion_matrix(labels, predictions, labels=[0, 1]).tolist(),
    }


def _legacy_split_summary(rows):
    counts = rows["label"].value_counts()
    return {
        "rows": len(rows),
        "class_counts": {str(label): int(counts.get(label, 0)) for label in (0, 1)},
        "unique_hostnames": rows["hostname"].nunique(),
    }


def _legacy_domain_groups(hostnames):
    groups = set()
    ungroupable = 0
    for hostname in hostnames:
        try:
            group = None if hostname == "invalid-host" else registrable_group(hostname)
        except UnicodeError:
            group = None
        if group:
            groups.add(group)
        else:
            ungroupable += 1
    return groups, ungroupable


def evaluate_legacy(data_path=DEFAULT_LEGACY_DATA, *, seed=42, include_diagnostics=False):
    """Refit the legacy experiment independently of shipped and Stage 3A models."""
    data_path = Path(data_path)
    rows = pd.read_csv(data_path)
    rows["url"] = rows["url"].astype(str).str.strip()
    rows["label"] = rows["label"].astype(int)
    rows["hostname"] = rows["url"].map(get_hostname)

    splitter = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=seed)
    train_indices, test_indices = next(splitter.split(rows, groups=rows["hostname"]))
    train, test = rows.iloc[train_indices], rows.iloc[test_indices]
    train_hosts, test_hosts = set(train["hostname"]), set(test["hostname"])
    hostname_overlap = train_hosts & test_hosts
    if hostname_overlap:
        raise RuntimeError(f"Legacy split has {len(hostname_overlap)} overlapping hostnames")
    train_domains, train_ungroupable = _legacy_domain_groups(train_hosts)
    test_domains, test_ungroupable = _legacy_domain_groups(test_hosts)

    model, vectorizer, scaler = fit_url_baseline(train["url"], train["label"], seed)
    features = transform_urls(test["url"], vectorizer, scaler)
    predictions = model.predict(features)
    metrics = binary_metrics(test["label"], predictions, model.predict_proba(features)[:, 1])
    report = {
        "dataset": str(data_path),
        "sha256": hashlib.sha256(data_path.read_bytes()).hexdigest(),
        "seed": seed,
        "grouping": "historical exact hostname",
        "train": {
            **_legacy_split_summary(train),
            "unique_registrable_groups": len(train_domains),
            "ungroupable_hostnames": train_ungroupable,
        },
        "test": {
            **_legacy_split_summary(test),
            "unique_registrable_groups": len(test_domains),
            "ungroupable_hostnames": test_ungroupable,
        },
        "hostname_overlap": len(hostname_overlap),
        "registrable_domain_overlap": len(train_domains & test_domains),
        "metrics": metrics,
        "dashboard_f1": DASHBOARD_URL_F1,
        "reproduces_dashboard_f1": round(metrics["f1"], 4) == DASHBOARD_URL_F1,
    }
    if include_diagnostics:
        report["classification_report"] = classification_report(
            test["label"], predictions, labels=[0, 1],
            target_names=["Legitimate", "Malicious"], zero_division=0,
        )
        diagnostic_features = transform_urls(DIAGNOSTIC_URLS, vectorizer, scaler)
        report["diagnostics"] = list(zip(
            DIAGNOSTIC_URLS,
            model.predict(diagnostic_features).tolist(),
            model.predict_proba(diagnostic_features).tolist(),
        ))
    return report


def main():
    parser = argparse.ArgumentParser(description="Reproduce the historical URL evaluation.")
    parser.add_argument("--data", type=Path, default=DEFAULT_LEGACY_DATA, help="Legacy urls.csv")
    args = parser.parse_args()
    if not args.data.is_file():
        parser.error(f"Historical evaluation dataset is missing: {args.data}")

    print("CYBERGUARD HISTORICAL URL EVALUATION", flush=True)
    report = evaluate_legacy(args.data, include_diagnostics=True)
    print(f"Seed: {report['seed']}")
    print(f"Dataset SHA-256: {report['sha256']}")
    for split in ("train", "test"):
        summary = report[split]
        print(f"{split.capitalize()}: {summary['rows']} rows, "
              f"classes {summary['class_counts']}, {summary['unique_hostnames']} hostnames")
    print(f"Train/test exact hostname overlap: {report['hostname_overlap']}")
    print(f"Train/test registrable group overlap: {report['registrable_domain_overlap']}")
    metrics = report["metrics"]
    for metric in ("accuracy", "precision", "recall", "f1", "average_precision"):
        print(f"{metric}: {metrics[metric]:.4f}")
    matches = "yes" if report["reproduces_dashboard_f1"] else "no"
    print(f"Dashboard F1: {report['dashboard_f1']:.2%}. "
          f"Reproduced F1: {metrics['f1']:.2%}. Match: {matches}.")
    print(f"Confusion matrix: {metrics['confusion_matrix']}")
    print(report["classification_report"])
    print("Historical URL diagnostics")
    for url, prediction, (legitimate, malicious) in report["diagnostics"]:
        result = "MALICIOUS" if prediction else "LEGITIMATE"
        print(f"{url} {result} (legitimate {legitimate:.2%}, malicious {malicious:.2%})")


if __name__ == "__main__":
    main()
