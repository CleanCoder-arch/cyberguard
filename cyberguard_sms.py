from detector_models import MODELS_DIR, explain_model, load_artifacts
from sms_risk_engine import analyze_message_risk


# ============================================================
# LOAD SMS MODEL
# ============================================================

MODEL_PATH = MODELS_DIR / "sms_model.joblib"
VECTORIZER_PATH = MODELS_DIR / "sms_vectorizer.joblib"


# ============================================================
# UNIFIED SMS ANALYZER
# ============================================================

def analyze_sms(message, *, detected_urls=None):

    message = str(message).strip()
    model, vectorizer = load_artifacts("SMS", MODEL_PATH, VECTORIZER_PATH)


    # --------------------------------------------------------
    # 1. TF-IDF
    # --------------------------------------------------------

    message_vector = vectorizer.transform(
        [message]
    )


    # --------------------------------------------------------
    # 2. ML PREDICTION
    # --------------------------------------------------------

    prediction = model.predict(
        message_vector
    )[0]


    probabilities = model.predict_proba(
        message_vector
    )[0]


    legitimate_probability = float(
        probabilities[0]
    )

    phishing_probability = float(
        probabilities[1]
    )


    if prediction == 1:

        ml_prediction = "PHISHING/SPAM"

    else:

        ml_prediction = "LEGITIMATE"


    # --------------------------------------------------------
    # 3. RISK ANALYSIS
    # --------------------------------------------------------

    risk_result = analyze_message_risk(
        message,
        phishing_probability,
        detected_urls=detected_urls,
    )


    # --------------------------------------------------------
    # 4. COMBINE RESULTS
    # --------------------------------------------------------

    result = {

        "message": message,

        "ml_prediction":
            ml_prediction,

        "legitimate_probability":
            legitimate_probability,

        "phishing_probability":
            phishing_probability,
        "model_explanation": explain_model(
            model,
            vectorizer,
            message_vector,
            positive_class="PHISHING/SPAM",
            text_kind="sms_tfidf",
        ),

        "risk_score":
            risk_result["risk_score"],
        "score_breakdown": risk_result["score_breakdown"],

        "risk_level":
            risk_result["risk_level"],

        "reasons":
            risk_result["reasons"],

        "positive_signals":
            risk_result["positive_signals"],

        "recommendation":
            risk_result["recommendation"],

        "detected_urls":
            risk_result["detected_urls"]
    }


    return result


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_messages = [

        "Hey, are we still meeting at 6 pm today?",

        "Your order has been shipped and will arrive tomorrow.",

        "Congratulations! You have won a free prize. "
        "Click this link now to claim your reward.",

        "URGENT! Your bank account has been suspended. "
        "Verify your account immediately by clicking this link.",

        "Your KYC verification is pending. "
        "Update your details immediately to avoid account closure.",

        "You have won Rs 50,000 in a lucky draw. "
        "Call now to claim your prize.",

        "Your account has been compromised. "
        "Click the link below and confirm your password immediately."
    ]


    print("\n" + "=" * 70)
    print("CYBERGUARD UNIFIED SMS ANALYZER")
    print("=" * 70)


    for message in test_messages:

        result = analyze_sms(
            message
        )


        print("\n" + "-" * 70)

        print(
            "Message:",
            result["message"]
        )

        print(
            "ML Prediction:",
            result["ml_prediction"]
        )

        print(
            "ML Phishing Probability:",
            f"{result['phishing_probability'] * 100:.2f}%"
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


        if result["detected_urls"]:

            print(
                "\nDetected URLs:",
                result["detected_urls"]
            )


        print(
            "\nRecommendation:",
            result["recommendation"]
        )
