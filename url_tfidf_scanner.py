import joblib


MODEL_PATH = "models/url_tfidf_model.joblib"
VECTORIZER_PATH = "models/url_tfidf_vectorizer.joblib"


print("Loading TF-IDF model...")

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

print("Model loaded successfully.")


def scan_url(url):

    url_vector = vectorizer.transform([url])

    prediction = model.predict(url_vector)[0]

    probabilities = model.predict_proba(url_vector)[0]

    legitimate_probability = probabilities[0]
    malicious_probability = probabilities[1]

    if prediction == 1:
        result = "MALICIOUS"
    else:
        result = "LEGITIMATE"

    return result, legitimate_probability, malicious_probability


if __name__ == "__main__":

    test_urls = [
        "https://google.com",
        "https://github.com",
        "https://www.microsoft.com",
        "https://www.amazon.com",
        "https://example.com",
        "http://secure-login-bank.xyz/verify",
        "http://paypal-login-security.xyz/login",
        "https://www.wikipedia.org",
        "https://www.youtube.com"
    ]

    print("\n" + "=" * 70)
    print("CYBERGUARD TF-IDF URL SCANNER")
    print("=" * 70)

    for url in test_urls:

        result, legitimate, malicious = scan_url(url)

        print("\nURL:", url)
        print("Prediction:", result)
        print("Legitimate:", f"{legitimate * 100:.2f}%")
        print("Malicious :", f"{malicious * 100:.2f}%")