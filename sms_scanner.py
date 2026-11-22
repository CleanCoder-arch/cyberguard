import joblib


# ============================================================
# LOAD SMS MODEL
# ============================================================

MODEL_PATH = "models/sms_model.joblib"
VECTORIZER_PATH = "models/sms_vectorizer.joblib"


print("Loading CyberGuard SMS detector...")

model = joblib.load(
    MODEL_PATH
)

vectorizer = joblib.load(
    VECTORIZER_PATH
)

print("SMS detector loaded successfully.")


# ============================================================
# SMS ANALYSIS FUNCTION
# ============================================================

def analyze_message(message):

    message = str(message).strip()


    # Convert message into TF-IDF
    message_vector = vectorizer.transform(
        [message]
    )


    # Prediction
    prediction = model.predict(
        message_vector
    )[0]


    # Probability
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

        result = "PHISHING/SPAM"

    else:

        result = "LEGITIMATE"


    return {
        "message": message,

        "prediction": result,

        "legitimate_probability":
            legitimate_probability,

        "phishing_probability":
            phishing_probability
    }


# ============================================================
# TEST MESSAGES
# ============================================================

if __name__ == "__main__":

    test_messages = [

        # ----------------------------------------------------
        # LEGITIMATE
        # ----------------------------------------------------

        "Hey, are we still meeting at 6 pm today?",

        "Your order has been shipped and will arrive tomorrow.",

        "Can you please send me the project report?",

        "Happy birthday! Have a wonderful day.",


        # ----------------------------------------------------
        # SUSPICIOUS / PHISHING
        # ----------------------------------------------------

        "Congratulations! You have won a free prize. Click this link now to claim your reward.",

        "URGENT! Your bank account has been suspended. Verify your account immediately by clicking this link.",

        "Your KYC verification is pending. Update your details immediately to avoid account closure.",

        "You have won Rs 50,000 in a lucky draw. Call now to claim your prize.",

        "Your account has been compromised. Click the link below and confirm your password immediately."
    ]


    print("\n" + "=" * 70)
    print("CYBERGUARD SMS SCANNER")
    print("=" * 70)


    for message in test_messages:

        result = analyze_message(
            message
        )


        print("\n" + "-" * 70)

        print(
            "Message:",
            result["message"]
        )

        print(
            "Prediction:",
            result["prediction"]
        )

        print(
            "Legitimate:",
            f"{result['legitimate_probability'] * 100:.2f}%"
        )

        print(
            "Phishing/Spam:",
            f"{result['phishing_probability'] * 100:.2f}%"
        )