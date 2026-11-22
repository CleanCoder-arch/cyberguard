import joblib
import pandas as pd

from url_features import extract_features


# Load trained model
model = joblib.load(
    "models/url_model.joblib"
)


def scan_url(url):
    """
    Analyze a URL using the trained
    Random Forest model.
    """

    # Extract URL features
    features = extract_features(url)

    # Convert dictionary to DataFrame
    feature_df = pd.DataFrame(
        [features]
    )

    # Make prediction
    prediction = model.predict(
        feature_df
    )[0]

    # Get probability
    probabilities = model.predict_proba(
        feature_df
    )[0]

    # Probability of malicious class
    risk_score = probabilities[1] * 100

    # Convert prediction to readable result
    if prediction == 1:
        result = "Phishing / Malicious"
    else:
        result = "Legitimate / Safe"

    return {
        "url": url,
        "prediction": int(prediction),
        "result": result,
        "risk_score": round(
            risk_score,
            2
        )
    }


# ============================================
# TEST
# ============================================

if __name__ == "__main__":

    test_urls = [
        "https://google.com",
        "https://github.com",
        "http://secure-login-bank.xyz/verify"
    ]

    for url in test_urls:

        result = scan_url(url)

        print("\n" + "=" * 50)

        print(
            "URL:",
            result["url"]
        )

        print(
            "Result:",
            result["result"]
        )

        print(
            "Risk Score:",
            result["risk_score"],
            "%"
        )