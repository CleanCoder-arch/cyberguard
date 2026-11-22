import pandas as pd
import joblib

from url_features import extract_features


# Load trained model
model = joblib.load(
    "models/url_model.joblib"
)

# URLs we want to investigate
test_urls = [
    "https://google.com",
    "https://github.com",
    "https://example.com",
    "http://secure-login-bank.xyz/verify",
    "https://www.microsoft.com",
    "https://www.amazon.com"
]


for url in test_urls:

    features = extract_features(url)

    feature_df = pd.DataFrame(
        [features]
    )

    prediction = model.predict(
        feature_df
    )[0]

    probabilities = model.predict_proba(
        feature_df
    )[0]

    print("\n" + "=" * 60)

    print("URL:", url)

    print("\nFeatures:")

    for name, value in features.items():
        print(
            f"{name:20} : {value}"
        )

    print("\nPrediction:")

    if prediction == 1:
        print("Phishing / Malicious")
    else:
        print("Legitimate / Safe")

    print(
        "Legitimate probability:",
        round(probabilities[0] * 100, 2),
        "%"
    )

    print(
        "Malicious probability:",
        round(probabilities[1] * 100, 2),
        "%"
    )