import pandas as pd
from scipy.sparse import hstack, csr_matrix

from detector_models import MODELS_DIR, explain_model, load_artifacts
from url_features import extract_features
from risk_engine import analyze_risk
from url_normalizer import normalize_url


# ============================================================
# LOAD MODELS
# ============================================================

MODEL_PATH = MODELS_DIR / "url_hybrid_model.joblib"
VECTORIZER_PATH = MODELS_DIR / "url_hybrid_vectorizer.joblib"
SCALER_PATH = MODELS_DIR / "url_hybrid_scaler.joblib"


# ============================================================
# MAIN URL ANALYSIS FUNCTION
# ============================================================

def analyze_url(url):

    # --------------------------------------------------------
    # 0. NORMALIZE URL
    # --------------------------------------------------------

    model_url, explicit_scheme = normalize_url(url)
    original_url = str(url).strip()
    scheme = model_url.split(":", 1)[0] if explicit_scheme else "unknown"
    display_url = model_url if explicit_scheme else model_url.removeprefix("http://")
    model, vectorizer, scaler = load_artifacts(
        "URL", MODEL_PATH, VECTORIZER_PATH, SCALER_PATH
    )

    # --------------------------------------------------------
    # 1. TF-IDF FEATURES
    # --------------------------------------------------------

    tfidf_features = vectorizer.transform(
        [model_url]
    )

    # --------------------------------------------------------
    # 2. HANDCRAFTED FEATURES
    # --------------------------------------------------------

    feature_dict = extract_features(
        model_url
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
        model_url,
        malicious_probability,
        feature_dict,
        scheme=scheme
    )

    # --------------------------------------------------------
    # 7. COMBINE RESULTS
    # --------------------------------------------------------

    result = {

        # Original user input
        "original_url":
            original_url,

        # Normalized URL as supplied, without an inferred scheme
        "url":
            display_url,

        "scheme":
            scheme,

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
        "model_explanation": explain_model(
            model,
            vectorizer,
            hybrid_features,
            positive_class="MALICIOUS",
            text_kind="url_tfidf",
            structure=feature_dict,
        ),

        # Risk result
        "risk_score":
            risk_result["risk_score"],
        "score_breakdown": risk_result["score_breakdown"],

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
            feature_dict,
        "checks": [{"check": "URL analysis", "status": "completed"}],
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
                "Scheme:",
                result["scheme"]
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
