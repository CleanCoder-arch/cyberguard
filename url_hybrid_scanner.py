import joblib
import pandas as pd

from scipy.sparse import hstack, csr_matrix

from url_features import extract_features


MODEL_PATH = "models/url_hybrid_model.joblib"
VECTORIZER_PATH = "models/url_hybrid_vectorizer.joblib"
SCALER_PATH = "models/url_hybrid_scaler.joblib"


print("Loading CyberGuard Hybrid URL Model...")

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)
scaler = joblib.load(SCALER_PATH)

print("Model loaded successfully.")


def scan_url(url):

    # -----------------------------------------
    # 1. TF-IDF FEATURES
    # -----------------------------------------

    tfidf_features = vectorizer.transform([url])


    # -----------------------------------------
    # 2. HANDCRAFTED FEATURES
    # -----------------------------------------

    feature_dict = extract_features(url)

    feature_df = pd.DataFrame([feature_dict])

    feature_df = feature_df.astype(float)


    # -----------------------------------------
    # 3. SCALE HANDCRAFTED FEATURES
    # -----------------------------------------

    scaled_features = scaler.transform(
        feature_df
    )

    scaled_features = csr_matrix(
        scaled_features
    )


    # -----------------------------------------
    # 4. COMBINE FEATURES
    # -----------------------------------------

    hybrid_features = hstack([
        tfidf_features,
        scaled_features
    ])


    # -----------------------------------------
    # 5. PREDICTION
    # -----------------------------------------

    prediction = model.predict(
        hybrid_features
    )[0]

    probabilities = model.predict_proba(
        hybrid_features
    )[0]


    legitimate_probability = probabilities[0]
    malicious_probability = probabilities[1]


    if prediction == 1:
        result = "MALICIOUS"
    else:
        result = "LEGITIMATE"


    return (
        result,
        legitimate_probability,
        malicious_probability
    )


if __name__ == "__main__":

    test_urls = [

        # Known legitimate websites
        "https://google.com",
        "https://github.com",
        "https://www.microsoft.com",
        "https://www.amazon.com",
        "https://example.com",
        "https://www.wikipedia.org",
        "https://www.youtube.com",

        # Suspicious URLs
        "http://secure-login-bank.xyz/verify",
        "http://paypal-login-security.xyz/login",
        "http://secure-account-verification.xyz/login"
    ]


    print("\n" + "=" * 70)
    print("CYBERGUARD HYBRID URL SCANNER")
    print("=" * 70)


    for url in test_urls:

        result, legitimate, malicious = scan_url(url)


        print("\nURL:", url)

        print(
            "Prediction:",
            result
        )

        print(
            "Legitimate:",
            f"{legitimate * 100:.2f}%"
        )

        print(
            "Malicious :",
            f"{malicious * 100:.2f}%"
        )