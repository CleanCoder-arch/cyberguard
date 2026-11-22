from cyberguard_url import analyze_url
from cyberguard_sms import analyze_sms
from sms_url_extractor import extract_urls


# ============================================================
# CYBERGUARD COMBINED ANALYZER
# ============================================================


def calculate_combined_risk(
    sms_result,
    url_results
):
    """
    Combine SMS risk with multiple URL risks.

    Strategy:
    - Start with the highest SMS/URL risk.
    - Add a small bonus for additional suspicious URLs.
    - Cap the final score at 100.
    """

    sms_score = sms_result.get(
        "risk_score",
        0
    )

    # --------------------------------------------------------
    # Collect valid URL scores
    # --------------------------------------------------------

    url_scores = []

    for url_result in url_results:

        score = url_result.get(
            "risk_score",
            0
        )

        url_scores.append(
            score
        )

    # --------------------------------------------------------
    # Base risk
    # --------------------------------------------------------

    all_scores = [
        sms_score,
        *url_scores
    ]

    base_score = max(
        all_scores
    )

    # --------------------------------------------------------
    # Additional suspicious URLs
    # --------------------------------------------------------

    suspicious_urls = [
        score
        for score in url_scores
        if score >= 30
    ]

    additional_suspicious_urls = max(
        0,
        len(suspicious_urls) - 1
    )

    # --------------------------------------------------------
    # Multi-URL bonus
    # --------------------------------------------------------

    multi_url_bonus = (
        additional_suspicious_urls * 10
    )

    combined_score = (
        base_score +
        multi_url_bonus
    )

    # --------------------------------------------------------
    # Cap score
    # --------------------------------------------------------

    combined_score = min(
        combined_score,
        100
    )

    # --------------------------------------------------------
    # Risk level
    # --------------------------------------------------------

    if combined_score >= 60:

        combined_level = "HIGH"

    elif combined_score >= 30:

        combined_level = "MEDIUM"

    else:

        combined_level = "LOW"

    # --------------------------------------------------------
    # Recommendation
    # --------------------------------------------------------

    if combined_level == "HIGH":

        recommendation = (
            "Avoid interacting with this message or its links. "
            "Do not enter passwords, financial information, "
            "or other sensitive data."
        )

    elif combined_level == "MEDIUM":

        recommendation = (
            "Proceed with caution. Verify the message and "
            "destination URLs before taking action."
        )

    else:

        recommendation = (
            "No strong combined risk indicators were detected, "
            "but continue to verify the message and links."
        )

    return {
        "risk_score": combined_score,
        "risk_level": combined_level,
        "recommendation": recommendation,

        # Additional transparency
        "base_score": base_score,
        "multi_url_bonus": multi_url_bonus,
        "suspicious_url_count": len(
            suspicious_urls
        )
    }


# ============================================================
# MAIN ANALYZER
# ============================================================

def analyze_input(
    input_type,
    content
):
    """
    Analyze either a URL or an SMS message.
    """

    # ========================================================
    # URL
    # ========================================================

    if input_type.upper() == "URL":

        return analyze_url(
            content
        )

    # ========================================================
    # SMS
    # ========================================================

    elif input_type.upper() == "SMS":

        # ----------------------------------------------------
        # 1. Extract URLs for both SMS scoring and embedded-link checks
        # --------------------------------------------------------

        detected_urls = []
        url_extraction_error = None
        try:
            detected_urls = extract_urls(content)
        except Exception as error:
            url_extraction_error = str(error) or "The link extraction check failed."

        # --------------------------------------------------------
        # 2. Analyze the SMS, including link signals when extraction succeeds
        # --------------------------------------------------------

        sms_result = None
        sms_error = None
        try:
            sms_result = analyze_sms(content, detected_urls=detected_urls)
        except Exception as error:
            sms_error = str(error) or "The SMS check failed."

        # --------------------------------------------------------
        # 3. Analyze every URL
        # --------------------------------------------------------

        url_results = []

        for url in detected_urls:

            try:

                url_result = analyze_url(
                    url
                )

                url_results.append(
                    url_result
                )

            except Exception as error:

                url_results.append({

                    "url": url,

                    "error": str(error) or "The URL check failed."

                })

        # ----------------------------------------------------
        # 4. Calculate combined risk
        # ----------------------------------------------------

        combined_result = None
        if (
            sms_result is not None
            and url_extraction_error is None
            and all("error" not in result for result in url_results)
        ):
            combined_result = calculate_combined_risk(sms_result, url_results)

        # ----------------------------------------------------
        # 5. Return the available results
        # ----------------------------------------------------

        result = {

            "input_type": "SMS",

            "content": content,

            "sms_result": sms_result,

            "detected_urls": detected_urls,

            "url_results": url_results,

            "combined_risk": combined_result

        }
        if sms_error is not None:
            result["sms_error"] = sms_error
        if url_extraction_error is not None:
            result["url_extraction_error"] = url_extraction_error
        return result

    # ========================================================
    # INVALID TYPE
    # ========================================================

    else:

        raise ValueError(
            "input_type must be either 'URL' or 'SMS'"
        )


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    def print_combined_risk(result):
        if "sms_error" in result:
            print("SMS check:", result["sms_error"])
        if "url_extraction_error" in result:
            print("Link extraction:", result["url_extraction_error"])
        combined_risk = result["combined_risk"]
        if combined_risk is None:
            print("Overall risk unavailable because a check failed.")
            return
        print("Combined Risk:", combined_risk["risk_score"])
        print("Combined Risk Level:", combined_risk["risk_level"])
        print("Recommendation:", combined_risk["recommendation"])

    print("\n" + "=" * 70)
    print("CYBERGUARD COMBINED ANALYZER")
    print("=" * 70)


    # --------------------------------------------------------
    # TEST 1 — SMS without URL
    # --------------------------------------------------------

    sms_1 = (
        "Your meeting is scheduled for tomorrow "
        "at 10 AM."
    )

    print("\n" + "-" * 70)
    print("TEST 1 — NORMAL SMS")
    print("-" * 70)

    result = analyze_input(
        "SMS",
        sms_1
    )

    print(
        "SMS:",
        result["content"]
    )

    print(
        "Detected URLs:",
        result["detected_urls"]
    )

    print_combined_risk(result)


    # --------------------------------------------------------
    # TEST 2 — SMS with phishing URL
    # --------------------------------------------------------

    sms_2 = (
        "URGENT! Your bank account has been suspended. "
        "Verify immediately at "
        "http://secure-login-bank.xyz/verify"
    )

    print("\n" + "-" * 70)
    print("TEST 2 — PHISHING SMS + URL")
    print("-" * 70)

    result = analyze_input(
        "SMS",
        sms_2
    )

    print(
        "SMS:",
        result["content"]
    )

    print(
        "Detected URLs:",
        result["detected_urls"]
    )

    for url_result in result["url_results"]:

        if "error" in url_result:

            print(
                "\nURL:",
                url_result["url"]
            )

            print(
                "ERROR:",
                url_result["error"]
            )

            continue

        print(
            "\nURL:",
            url_result["url"]
        )

        print(
            "ML Malicious Probability:",
            f"{url_result['malicious_probability'] * 100:.2f}%"
        )

        print(
            "Risk Score:",
            url_result["risk_score"]
        )

        print(
            "Risk Level:",
            url_result["risk_level"]
        )


    print_combined_risk(result)


    # --------------------------------------------------------
    # TEST 3 — Multiple URLs
    # --------------------------------------------------------

    sms_3 = (
        "Security alert! Visit "
        "http://evil1.xyz/login "
        "or "
        "https://evil2.top/verify"
    )

    print("\n" + "-" * 70)
    print("TEST 3 — MULTIPLE URLS")
    print("-" * 70)

    result = analyze_input(
        "SMS",
        sms_3
    )

    print(
        "SMS:",
        result["content"]
    )

    print(
        "Detected URLs:",
        result["detected_urls"]
    )

    for index, url_result in enumerate(
        result["url_results"],
        start=1
    ):

        print(
            f"\nURL {index}:",
            url_result["url"]
        )

        if "error" in url_result:
            print("ERROR:", url_result["error"])
            continue

        print(
            "Risk Score:",
            url_result["risk_score"]
        )

        print(
            "Risk Level:",
            url_result["risk_level"]
        )

    print_combined_risk(result)


    print("\n" + "=" * 70)
    print("CYBERGUARD COMBINED ANALYZER TEST COMPLETE")
    print("=" * 70)
