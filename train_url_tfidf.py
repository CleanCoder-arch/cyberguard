import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# 1. LOAD DATA
# ============================================================

print("Loading URL dataset...")

df = pd.read_csv("data/urls.csv")

df["url"] = (
    df["url"]
    .astype(str)
    .str.strip()
)

y = df["label"]

print("Total URLs:", len(df))


# ============================================================
# 2. TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    df["url"],
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("Training URLs:", len(X_train))
print("Testing URLs :", len(X_test))


# ============================================================
# 3. CHARACTER-LEVEL TF-IDF
# ============================================================

print("\nBuilding character-level TF-IDF...")

vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(2, 5),
    min_df=2,
    max_features=50000,
    sublinear_tf=True
)

X_train_tfidf = vectorizer.fit_transform(
    X_train
)

X_test_tfidf = vectorizer.transform(
    X_test
)

print(
    "TF-IDF training shape:",
    X_train_tfidf.shape
)

print(
    "TF-IDF testing shape:",
    X_test_tfidf.shape
)


# ============================================================
# 4. TRAIN LOGISTIC REGRESSION
# ============================================================

print("\nTraining character-level Logistic Regression...")

model = LogisticRegression(
    max_iter=2000,
    C=5.0,
    random_state=42
)

model.fit(
    X_train_tfidf,
    y_train
)


# ============================================================
# 5. PREDICTION
# ============================================================

predictions = model.predict(
    X_test_tfidf
)


# ============================================================
# 6. EVALUATION
# ============================================================

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


print("\n" + "=" * 60)
print("CHARACTER TF-IDF MODEL RESULTS")
print("=" * 60)

print(
    "Accuracy :",
    round(accuracy, 4)
)

print(
    "Precision:",
    round(precision, 4)
)

print(
    "Recall   :",
    round(recall, 4)
)

print(
    "F1 Score :",
    round(f1, 4)
)


# ============================================================
# 7. CLASSIFICATION REPORT
# ============================================================

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


# ============================================================
# 8. CONFUSION MATRIX
# ============================================================

print("\nConfusion Matrix:")

cm = confusion_matrix(
    y_test,
    predictions
)

print(cm)


# ============================================================
# 9. SAVE MODEL
# ============================================================

joblib.dump(
    model,
    "models/url_tfidf_model.joblib"
)

joblib.dump(
    vectorizer,
    "models/url_tfidf_vectorizer.joblib"
)

print("\nSaved:")

print(
    "models/url_tfidf_model.joblib"
)

print(
    "models/url_tfidf_vectorizer.joblib"
)