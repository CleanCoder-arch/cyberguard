from sms_risk_engine import analyze_message_risk


test_messages = [

    {
        "message":
            "Hey, are we still meeting at 6 pm today?",

        "probability":
            0.0285
    },

    {
        "message":
            "Your order has been shipped and will arrive tomorrow.",

        "probability":
            0.3894
    },

    {
        "message":
            "Congratulations! You have won a free prize. "
            "Click this link now to claim your reward.",

        "probability":
            0.9932
    },

    {
        "message":
            "URGENT! Your bank account has been suspended. "
            "Verify your account immediately by clicking this link.",

        "probability":
            0.7350
    },

    {
        "message":
            "Your KYC verification is pending. "
            "Update your details immediately to avoid account closure.",

        "probability":
            0.4923
    },

    {
        "message":
            "You have won Rs 50,000 in a lucky draw. "
            "Call now to claim your prize.",

        "probability":
            0.9956
    },

    {
        "message":
            "Your account has been compromised. "
            "Click the link below and confirm your password immediately.",

        "probability":
            0.4939
    }
]


print("=" * 70)
print("CYBERGUARD SMS RISK ENGINE TEST")
print("=" * 70)


for item in test_messages:

    result = analyze_message_risk(
        item["message"],
        item["probability"]
    )


    print("\n" + "-" * 70)

    print(
        "Message:",
        result["message"]
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


    print(
        "\nRecommendation:",
        result["recommendation"]
    )