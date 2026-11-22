import pandas as pd
import joblib
import numpy as np

from scipy.sparse import hstack, csr_matrix

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

from url_features import extract_features


print("=" * 70)
print("CYBERGUARD HYBRID URL MODEL")
print("=" * 70)


# --------------------------------------------------
# 1. LOAD DATA
# --------------------------------------------------

print("\nLoading URL dataset...")

df = pd.read_csv("data/urls.csv")

df["url"] = (
    df["url"]
    .astype(str)
    .str.strip()
)

y = df["label"]

print("Total URLs:", len(df))


# --------------------------------------------------
# 2. TRAIN / TEST SPLIT
# --------------------------------------------------

X_train_urls, X_test_urls, y_train, y_test = train_test_split(
    df["url"],
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("Training URLs:", len(X_train_urls))
print("Testing URLs :", len(X_test_urls))


# --------------------------------------------------
# 3. CHARACTER TF-IDF
# --------------------------------------------------

print("\nBuilding character-level TF-IDF...")

vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(2, 5),
    min_df=2,
    max_features=50000,
    sublinear_tf=True
)

X_train_tfidf = vectorizer.fit_transform(X_train_urls)
X_test_tfidf = vectorizer.transform(X_test_urls)

print("TF-IDF training shape:", X_train_tfidf.shape)
print("TF-IDF testing shape :", X_test_tfidf.shape)


# --------------------------------------------------
# 4. HANDCRAFTED URL FEATURES
# --------------------------------------------------

print("\nExtracting handcrafted URL features...")

X_train_features = pd.DataFrame([
    extract_features(url)
    for url in X_train_urls
])

X_test_features = pd.DataFrame([
    extract_features(url)
    for url in X_test_urls
])

print(
    "Handcrafted training shape:",
    X_train_features.shape
)

print(
    "Handcrafted testing shape :",
    X_test_features.shape
)

print(
    "Number of handcrafted features:",
    len(X_train_features.columns)
)

print(
    "Feature names:",
    list(X_train_features.columns)
)


# --------------------------------------------------
# 5. SCALE HANDCRAFTED FEATURES
# --------------------------------------------------

print("\nScaling handcrafted features...")

scaler = StandardScaler()

X_train_features_scaled = scaler.fit_transform(
    X_train_features.astype(float)
)

X_test_features_scaled = scaler.transform(
    X_test_features.astype(float)
)


# Convert dense features to sparse format
X_train_features_sparse = csr_matrix(
    X_train_features_scaled
)

X_test_features_sparse = csr_matrix(
    X_test_features_scaled
)


# --------------------------------------------------
# 6. COMBINE TF-IDF + HANDCRAFTED FEATURES
# --------------------------------------------------

print("\nCombining features...")

X_train_hybrid = hstack([
    X_train_tfidf,
    X_train_features_sparse
])

X_test_hybrid = hstack([
    X_test_tfidf,
    X_test_features_sparse
])

print(
    "Hybrid training shape:",
    X_train_hybrid.shape
)

print(
    "Hybrid testing shape :",
    X_test_hybrid.shape
)


# --------------------------------------------------
# 7. TRAIN MODEL
# --------------------------------------------------

print("\nTraining Hybrid Logistic Regression...")

model = LogisticRegression(
    max_iter=2000,
    C=5.0,
    random_state=42
)

model.fit(
    X_train_hybrid,
    y_train
)


# --------------------------------------------------
# 8. PREDICTION
# --------------------------------------------------

predictions = model.predict(
    X_test_hybrid
)


# --------------------------------------------------
# 9. EVALUATION
# --------------------------------------------------

accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    zero_division=0
)

recall = recall_score(
    y_test,
    predictions,
    zero_division=0
)

f1 = f1_score(
    y_test,
    predictions,
    zero_division=0
)


print("\n" + "=" * 70)
print("HYBRID MODEL RESULTS")
print("=" * 70)

print("Accuracy :", round(accuracy, 4))
print("Precision:", round(precision, 4))
print("Recall   :", round(recall, 4))
print("F1 Score :", round(f1, 4))


print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions,
        target_names=[
            "Legitimate",
            "Malicious"
        ],
        zero_division=0
    )
)


print("\nConfusion Matrix:")

cm = confusion_matrix(
    y_test,
    predictions
)

print(cm)


# --------------------------------------------------
# 10. SAVE MODEL
# --------------------------------------------------

joblib.dump(
    model,
    "models/url_hybrid_model.joblib"
)

joblib.dump(
    vectorizer,
    "models/url_hybrid_vectorizer.joblib"
)

joblib.dump(
    scaler,
    "models/url_hybrid_scaler.joblib"
)


print("\nSaved:")

print(
    "models/url_hybrid_model.joblib"
)

print(
    "models/url_hybrid_vectorizer.joblib"
)

print(
    "models/url_hybrid_scaler.joblib"
)

print("\nHybrid model training completed.")