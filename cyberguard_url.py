import joblib
import pandas as pd

from scipy.sparse import hstack, csr_matrix

from url_features import extract_features
from risk_engine import analyze_risk
from url_normalizer import normalize_url


# ============================================================
# LOAD MODELS
# ============================================================

MODEL_PATH = "models/url_hybrid_model.joblib"
VECTORIZER_PATH = "models/url_hybrid_vectorizer.joblib"
SCALER_PATH = "models/url_hybrid_scaler.joblib"


print("Loading CyberGuard URL detector...")

model = joblib.load(MODEL_PATH)

vectorizer = joblib.load(
    VECTORIZER_PATH
)

scaler = joblib.load(
    SCALER_PATH
)

print("CyberGuard URL detector loaded.")


# ============================================================
# MAIN URL ANALYSIS FUNCTION
# ============================================================

def analyze_url(url):

    # --------------------------------------------------------
    # 0. NORMALIZE URL
    # --------------------------------------------------------

    original_url = str(url).strip()

    normalized_url, explicit_scheme = normalize_url(
        original_url
    )

    # --------------------------------------------------------
    # 1. TF-IDF FEATURES
    # --------------------------------------------------------

    tfidf_features = vectorizer.transform(
        [normalized_url]
    )

    # --------------------------------------------------------
    # 2. HANDCRAFTED FEATURES
    # --------------------------------------------------------

    feature_dict = extract_features(
        normalized_url
    )

    feature_df = pd.DataFrame(
        [feature_dict]
    )

    feature_df = feature_df.astype(float)

    # --------------------------------------------------------
    # 3. SCALE FEATURES
    # --------------------------------------------------------

    scaled_features = scaler.transform(
        feature_df
    )

    scaled_features = csr_matrix(
        scaled_features
    )

    # --------------------------------------------------------
    # 4. COMBINE FEATURES
    # --------------------------------------------------------

    hybrid_features = hstack([
        tfidf_features,
        scaled_features
    ])

    # --------------------------------------------------------
    # 5. ML PREDICTION
    # --------------------------------------------------------

    prediction = model.predict(
        hybrid_features
    )[0]

    probabilities = model.predict_proba(
        hybrid_features
    )[0]

    legitimate_probability = float(
        probabilities[0]
    )

    malicious_probability = float(
        probabilities[1]
    )

    if prediction == 1:

        ml_prediction = "MALICIOUS"

    else:

        ml_prediction = "LEGITIMATE"

    # --------------------------------------------------------
    # 6. RISK ANALYSIS
    # --------------------------------------------------------

    risk_result = analyze_risk(
        normalized_url,
        malicious_probability,
        feature_dict
    )

    # --------------------------------------------------------
    # 7. COMBINE RESULTS
    # --------------------------------------------------------

    result = {

        # Original user input
        "original_url":
            original_url,

        # Normalized URL used by CyberGuard
        "url":
            normalized_url,

        # Whether HTTP/HTTPS was explicitly provided
        "explicit_scheme":
            explicit_scheme,

        # ML result
        "ml_prediction":
            ml_prediction,

        "legitimate_probability":
            legitimate_probability,

        "malicious_probability":
            malicious_probability,

        # Risk result
        "risk_score":
            risk_result["risk_score"],

        "risk_level":
            risk_result["risk_level"],

        "hostname":
            risk_result["hostname"],

        "reasons":
            risk_result["reasons"],

        "positive_signals":
            risk_result["positive_signals"],

        "recommendation":
            risk_result["recommendation"],

        # Features
        "features":
            feature_dict
    }

    return result


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_urls = [

        # Normalized legitimate URLs
        "https://www.wikipedia.org",

        "https://www.microsoft.com",

        "https://google.com",

        "https://www.amazon.com",

        # URLs without scheme
        "google.com",

        "www.microsoft.com",

        # Phishing URLs
        "http://secure-login-bank.xyz/verify",

        "http://paypal-login-security.xyz/login"
    ]

    print("\n" + "=" * 70)
    print("CYBERGUARD UNIFIED URL ANALYZER")
    print("=" * 70)

    for url in test_urls:

        try:

            result = analyze_url(
                url
            )

            print("\n" + "-" * 70)

            print(
                "Original URL:",
                result["original_url"]
            )

            print(
                "Normalized URL:",
                result["url"]
            )

            print(
                "Explicit Scheme:",
                result["explicit_scheme"]
            )

            print(
                "Hostname:",
                result["hostname"]
            )

            print(
                "ML Prediction:",
                result["ml_prediction"]
            )

            print(
                "ML Malicious Probability:",
                f"{result['malicious_probability'] * 100:.2f}%"
            )

            print(
                "Risk Score:",
                f"{result['risk_score']}/100"
            )

            print(
                "Risk Level:",
                result["risk_level"]
            )

            print("\nReasons:")

            if result["reasons"]:

                for reason in result["reasons"]:

                    print(
                        "  ⚠",
                        reason
                    )

            else:

                print("  None")

            print("\nPositive Signals:")

            if result["positive_signals"]:

                for signal in result["positive_signals"]:

                    print(
                        "  ✓",
                        signal
                    )

            else:

                print("  None")

            print(
                "\nRecommendation:",
                result["recommendation"]
            )

        except Exception as e:

            print("\n" + "-" * 70)

            print(
                "URL:",
                url
            )

            print(
                "ERROR:",
                e
            )