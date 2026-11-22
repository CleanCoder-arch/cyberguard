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
# CYBERGUARD SMS PHISHING DETECTOR
# ============================================================

print("=" * 70)
print("CYBERGUARD SMS PHISHING DETECTOR")
print("=" * 70)


# ------------------------------------------------------------
# 1. LOAD DATASET
# ------------------------------------------------------------

print("\nLoading SMS dataset...")

df = pd.read_csv(
    "data/messages.csv"
)


# ------------------------------------------------------------
# 2. CLEAN DATA
# ------------------------------------------------------------

df["text"] = (
    df["text"]
    .astype(str)
    .str.strip()
)

df = df[
    df["text"].str.len() > 0
].copy()

df["label"] = df["label"].astype(int)


print("Total messages:", len(df))


print("\nClass distribution:")

print(
    df["label"].value_counts()
)


# ------------------------------------------------------------
# 3. TRAIN / TEST SPLIT
# ------------------------------------------------------------

print("\nCreating stratified train/test split...")

X_train, X_test, y_train, y_test = train_test_split(

    df["text"],

    df["label"],

    test_size=0.20,

    random_state=42,

    stratify=df["label"]
)


print(
    "Training messages:",
    len(X_train)
)

print(
    "Testing messages :",
    len(X_test)
)


print("\nTraining class distribution:")

print(
    y_train.value_counts()
)

print("\nTesting class distribution:")

print(
    y_test.value_counts()
)


# ------------------------------------------------------------
# 4. TF-IDF
# ------------------------------------------------------------

print("\nBuilding word-level TF-IDF...")

vectorizer = TfidfVectorizer(

    lowercase=True,

    strip_accents="unicode",

    ngram_range=(1, 2),

    min_df=2,

    max_features=30000,

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
    "TF-IDF testing shape :",
    X_test_tfidf.shape
)


# ------------------------------------------------------------
# 5. TRAIN LOGISTIC REGRESSION
# ------------------------------------------------------------

print("\nTraining Logistic Regression...")

model = LogisticRegression(

    max_iter=2000,

    class_weight="balanced",

    C=3.0,

    random_state=42
)


model.fit(
    X_train_tfidf,
    y_train
)


# ------------------------------------------------------------
# 6. PREDICTIONS
# ------------------------------------------------------------

print("\nGenerating predictions...")

predictions = model.predict(
    X_test_tfidf
)


# ------------------------------------------------------------
# 7. PROBABILITIES
# ------------------------------------------------------------

probabilities = model.predict_proba(
    X_test_tfidf
)

malicious_probabilities = probabilities[:, 1]


# ------------------------------------------------------------
# 8. EVALUATION
# ------------------------------------------------------------

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
print("SMS MODEL RESULTS")
print("=" * 70)

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


# ------------------------------------------------------------
# 9. CLASSIFICATION REPORT
# ------------------------------------------------------------

print("\nClassification Report:")

print(
    classification_report(

        y_test,

        predictions,

        target_names=[
            "Legitimate",
            "Phishing/Spam"
        ],

        zero_division=0
    )
)


# ------------------------------------------------------------
# 10. CONFUSION MATRIX
# ------------------------------------------------------------

print("\nConfusion Matrix:")

cm = confusion_matrix(
    y_test,
    predictions
)

print(cm)


# ------------------------------------------------------------
# 11. SAVE MODEL
# ------------------------------------------------------------

joblib.dump(
    model,
    "models/sms_model.joblib"
)

joblib.dump(
    vectorizer,
    "models/sms_vectorizer.joblib"
)


print("\nSaved:")

print(
    "models/sms_model.joblib"
)

print(
    "models/sms_vectorizer.joblib"
)


print("\nSMS model training completed.")