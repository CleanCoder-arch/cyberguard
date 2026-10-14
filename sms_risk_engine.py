import re


# ============================================================
# CYBERGUARD SMS RISK ANALYSIS ENGINE
# ============================================================


# Words/phrases associated with urgency.
URGENCY_KEYWORDS = {
    "urgent",
    "immediately",
    "now",
    "hurry",
    "asap",
    "expires",
    "expired",
    "final warning",
    "act now",
    "within 24 hours",
}


# Account/security-related terms.
ACCOUNT_KEYWORDS = {
    "account",
    "bank account",
    "login",
    "signin",
    "sign in",
    "kyc",
    "verification",
    "verify",
    "suspended",
    "suspension",
    "blocked",
    "security",
    "compromised",
}


# Credential-related terms.
CREDENTIAL_KEYWORDS = {
    "password",
    "passcode",
    "pin",
    "otp",
    "cvv",
    "credential",
    "username",
    "card details",
    "bank details",
}


# Financial/payment-related terms.
FINANCIAL_KEYWORDS = {
    "bank",
    "payment",
    "pay",
    "transfer",
    "refund",
    "money",
    "cash",
    "loan",
    "credit",
    "debit",
    "wallet",
    "transaction",
}


# Prize/scam-related terms.
PRIZE_KEYWORDS = {
    "won",
    "winner",
    "winning",
    "prize",
    "reward",
    "lucky draw",
    "lottery",
    "free prize",
    "claim",
    "cash prize",
}


def detect_urls(message):
    """
    Detect URLs inside a message.
    """

    pattern = r"(https?://\S+|www\.\S+|\b[a-zA-Z0-9-]+\.(com|in|org|net|xyz|co|info|site)\b)"

    return re.findall(
        pattern,
        message,
        flags=re.IGNORECASE
    )


def analyze_message_risk(
    message,
    phishing_probability
):
    """
    Analyze an SMS/message using ML probability
    plus explainable security heuristics.
    """

    message = str(message).strip()

    text = message.lower()


    score = 0

    reasons = []

    positive_signals = []


    # --------------------------------------------------------
    # 1. ML SIGNAL
    # --------------------------------------------------------

    if phishing_probability >= 0.80:

        score += 35

        reasons.append(
            "ML detector shows a high phishing probability."
        )

    elif phishing_probability >= 0.60:

        score += 25

        reasons.append(
            "ML detector shows an elevated phishing probability."
        )

    elif phishing_probability >= 0.40:

        score += 10

        reasons.append(
            "ML detector shows some phishing indicators."
        )

    else:

        positive_signals.append(
            "ML detector shows a relatively low phishing probability."
        )


    # --------------------------------------------------------
    # 2. URGENCY
    # --------------------------------------------------------

    matched_urgency = [
        word
        for word in URGENCY_KEYWORDS
        if word in text
    ]

    if matched_urgency:

        score += min(
            len(matched_urgency) * 5,
            15
        )

        reasons.append(
            "Urgency or pressure language detected: "
            + ", ".join(sorted(matched_urgency))
            + "."
        )


    # --------------------------------------------------------
    # 3. ACCOUNT / SECURITY
    # --------------------------------------------------------

    matched_account = [
        word
        for word in ACCOUNT_KEYWORDS
        if word in text
    ]

    if matched_account:

        score += min(
            len(matched_account) * 4,
            15
        )

        reasons.append(
            "Account/security-related language detected: "
            + ", ".join(sorted(matched_account))
            + "."
        )


    # --------------------------------------------------------
    # 4. CREDENTIAL REQUEST
    # --------------------------------------------------------

    matched_credentials = [
        word
        for word in CREDENTIAL_KEYWORDS
        if word in text
    ]

    if matched_credentials:

        score += min(
            len(matched_credentials) * 8,
            20
        )

        reasons.append(
            "Credential or sensitive-information language detected: "
            + ", ".join(sorted(matched_credentials))
            + "."
        )


    # --------------------------------------------------------
    # 5. FINANCIAL LANGUAGE
    # --------------------------------------------------------

    matched_financial = [
        word
        for word in FINANCIAL_KEYWORDS
        if word in text
    ]

    if matched_financial:

        score += min(
            len(matched_financial) * 3,
            15
        )

        reasons.append(
            "Financial/payment-related language detected: "
            + ", ".join(sorted(matched_financial))
            + "."
        )


    # --------------------------------------------------------
    # 6. PRIZE / REWARD LANGUAGE
    # --------------------------------------------------------

    matched_prize = [
        word
        for word in PRIZE_KEYWORDS
        if word in text
    ]

    if matched_prize:

        score += min(
            len(matched_prize) * 5,
            20
        )

        reasons.append(
            "Prize/reward or claim language detected: "
            + ", ".join(sorted(matched_prize))
            + "."
        )


    # --------------------------------------------------------
    # 7. URL / LINK
    # --------------------------------------------------------

    urls = detect_urls(
        message
    )

    if urls:

        score += 15

        reasons.append(
            "Message contains a web link or URL."
        )


    # --------------------------------------------------------
    # 8. SUSPICIOUS COMBINATION
    # --------------------------------------------------------

    has_urgency = bool(matched_urgency)
    has_account = bool(matched_account)
    has_credentials = bool(matched_credentials)
    has_financial = bool(matched_financial)
    has_prize = bool(matched_prize)

    if (
        has_urgency
        and (
            has_account
            or has_credentials
            or has_financial
        )
    ):

        score += 15

        reasons.append(
            "Urgency is combined with account, "
            "credential, or financial-related content."
        )


    if has_prize and urls:

        score += 15

        reasons.append(
            "Prize/reward language is combined with a web link."
        )


    # --------------------------------------------------------
    # 9. SCORE LIMIT
    # --------------------------------------------------------

    score = max(
        0,
        min(score, 100)
    )


    # --------------------------------------------------------
    # 10. RISK LEVEL
    # --------------------------------------------------------

    if score >= 60:

        risk_level = "HIGH"

    elif score >= 30:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    # --------------------------------------------------------
    # 11. RECOMMENDATION
    # --------------------------------------------------------

    if risk_level == "HIGH":

        recommendation = (
            "Do not click links or provide passwords, "
            "OTP codes, banking details, or other sensitive information."
        )

    elif risk_level == "MEDIUM":

        recommendation = (
            "Proceed with caution. Verify the sender and "
            "message through an official channel before taking action."
        )

    else:

        recommendation = (
            "No strong phishing indicators were detected, "
            "but remain cautious with unexpected messages."
        )


    # --------------------------------------------------------
    # 12. RETURN
    # --------------------------------------------------------

    return {

        "message": message,

        "risk_score": score,

        "risk_level": risk_level,

        "phishing_probability":
            phishing_probability,

        "reasons": reasons,

        "positive_signals":
            positive_signals,

        "recommendation":
            recommendation,

        "detected_urls":
            urls,
    }