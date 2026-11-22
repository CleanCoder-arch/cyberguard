import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)

from url_features import extract_features


# ============================================
# 1. LOAD DATA
# ============================================

print("Loading URL dataset...")

df = pd.read_csv("data/urls.csv")

print("Total rows:", len(df))


# ============================================
# 2. EXTRACT FEATURES
# ============================================

print("\nExtracting URL features...")

feature_rows = []

for url in df["url"]:
    feature_rows.append(
        extract_features(url)
    )

X = pd.DataFrame(feature_rows)

y = df["label"]

print("Features extracted:", X.shape[1])
print("Feature rows:", X.shape[0])


# ============================================
# 3. TRAIN / TEST SPLIT
# ============================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# ============================================
# 4. DEFINE MODELS
# ============================================

models = {

    "Random Forest": RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    ),

    "Logistic Regression": LogisticRegression(
        max_iter=1000,
        random_state=42
    ),

    "Gradient Boosting": GradientBoostingClassifier(
        random_state=42
    )
}


# ============================================
# 5. TRAIN AND EVALUATE
# ============================================

results = []

trained_models = {}

for name, model in models.items():

    print("\n" + "=" * 50)
    print("Training:", name)
    print("=" * 50)

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

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

    print("Accuracy :", round(accuracy, 4))
    print("Precision:", round(precision, 4))
    print("Recall   :", round(recall, 4))
    print("F1 Score :", round(f1, 4))

    results.append({
        "Model": name,
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1": f1
    })

    trained_models[name] = model


# ============================================
# 6. DISPLAY MODEL COMPARISON
# ============================================

results_df = pd.DataFrame(results)

print("\n")
print("=" * 60)
print("MODEL COMPARISON")
print("=" * 60)

print(
    results_df.sort_values(
        "F1",
        ascending=False
    ).to_string(index=False)
)


# ============================================
# 7. SELECT BEST MODEL
# ============================================

best_model_name = (
    results_df
    .sort_values("F1", ascending=False)
    .iloc[0]["Model"]
)

best_model = trained_models[
    best_model_name
]

print("\nBest model based on F1 score:")
print(best_model_name)


# ============================================
# 8. SAVE BEST MODEL
# ============================================

joblib.dump(
    best_model,
    "models/url_model.joblib"
)

# Save the feature names too.
joblib.dump(
    list(X.columns),
    "models/url_features.joblib"
)

print("\nSaved:")
print("models/url_model.joblib")
print("models/url_features.joblib")