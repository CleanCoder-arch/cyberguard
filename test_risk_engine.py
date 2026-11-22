from risk_engine import analyze_risk
from url_features import extract_features


test_cases = [

    {
        "url": "https://www.wikipedia.org",
        "malicious_probability": 0.025
    },

    {
        "url": "https://www.microsoft.com",
        "malicious_probability": 0.0993
    },

    {
        "url": "http://secure-login-bank.xyz/verify",
        "malicious_probability": 1.00
    },

    {
        "url": "http://paypal-login-security.xyz/login",
        "malicious_probability": 1.00
    },

    {
        "url": "https://google.com",
        "malicious_probability": 0.8496
    }
]


print("=" * 70)
print("CYBERGUARD RISK ENGINE TEST")
print("=" * 70)


for item in test_cases:

    url = item["url"]

    malicious_probability = item[
        "malicious_probability"
    ]

    features = extract_features(url)

    result = analyze_risk(
        url,
        malicious_probability,
        features
    )


    print("\n" + "-" * 70)

    print("URL:", result["url"])

    print(
        "Risk Score:",
        result["risk_score"],
        "/ 100"
    )

    print(
        "Risk Level:",
        result["risk_level"]
    )

    print(
        "ML Malicious Probability:",
        f"{result['malicious_probability'] * 100:.2f}%"
    )


    print("\nReasons:")

    if result["reasons"]:

        for reason in result["reasons"]:

            print("  ⚠", reason)

    else:

        print("  None")


    print("\nPositive Signals:")

    if result["positive_signals"]:

        for signal in result["positive_signals"]:

            print("  ✓", signal)

    else:

        print("  None")


    print(
        "\nRecommendation:",
        result["recommendation"]
    )