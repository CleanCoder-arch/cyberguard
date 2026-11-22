from urllib.parse import urlparse, parse_qs, unquote
from ipaddress import ip_address
import re


# ============================================================
# CYBERGUARD RISK ANALYSIS ENGINE
# ============================================================


# These are used only as a positive signal.
# They do NOT guarantee that every URL under these domains is safe.
TRUSTED_DOMAINS = {
    "google.com",
    "github.com",
    "microsoft.com",
    "amazon.com",
    "wikipedia.org",
    "youtube.com",
}


# TLDs that are commonly observed in suspicious URL datasets.
# This is only a heuristic signal.
SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".zip",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
}


# Words frequently associated with phishing-style URLs.
SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "confirm",
    "bank",
    "password",
    "credential",
    "payment",
    "wallet",
    "authenticate",
    "authentication",
}


# ============================================================
# HOSTNAME
# ============================================================

def get_hostname(url):
    """
    Extract hostname safely from a URL.
    """

    try:

        value = str(url).strip()

        if not value.lower().startswith(("http://", "https://")):
            value = "http://" + value.removeprefix("//")

        parsed = urlparse(value)

        hostname = parsed.hostname

        if hostname:
            return hostname

        return ""

    except Exception:

        return ""


# ============================================================
# ROOT DOMAIN
# ============================================================

def get_root_domain(hostname):
    """
    Get a simple root-domain representation.

    Examples:
        www.google.com -> google.com
        google.com     -> google.com
    """

    if not hostname:
        return ""

    hostname = hostname.lower().strip(".")

    if hostname.startswith("www."):
        hostname = hostname[4:]

    parts = hostname.split(".")

    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return hostname


# ============================================================
# BRAND IMPERSONATION
# ============================================================

def detect_brand_impersonation(hostname):
    """
    Detect trusted brand/domain names appearing inside
    a different hostname.

    Examples:

        google.com
            -> None

        login.google.com
            -> None

        google.com.evil-site.xyz
            -> google.com

        microsoft.com.fake-login.xyz
            -> microsoft.com

    This checks the HOSTNAME only.
    It intentionally does not inspect the URL path/query.
    """

    if not hostname:
        return None

    hostname = hostname.lower().strip(".")

    root_domain = get_root_domain(hostname)

    # Legitimate trusted domain or its subdomain
    if root_domain in TRUSTED_DOMAINS:
        return None

    for trusted_domain in TRUSTED_DOMAINS:

        if (
            trusted_domain in hostname
            and hostname != trusted_domain
            and not hostname.endswith(
                "." + trusted_domain
            )
        ):

            return trusted_domain

    return None


# ============================================================
# NESTED URL / REDIRECT DETECTION
# ============================================================

def detect_nested_urls(url):
    """
    Detect URLs embedded inside query parameters.

    Example:
        http://evil.xyz/?redirect=https://google.com

    Also detects URL-encoded values such as:
        ?redirect=https%3A%2F%2Fgoogle.com

    Returns:
        List of embedded URLs.
    """

    nested_urls = []

    try:

        parsed = urlparse(
            str(url)
        )

        query_values = parse_qs(
            parsed.query,
            keep_blank_values=True
        )

        for values in query_values.values():

            for value in values:

                decoded_value = unquote(
                    value
                ).strip()

                if decoded_value.startswith(
                    ("http://", "https://")
                ):

                    nested_urls.append(
                        decoded_value
                    )

    except Exception:

        return []

    return nested_urls


# ============================================================
# MAIN RISK ANALYSIS
# ============================================================

def analyze_risk(url, malicious_probability, features, *, scheme=None):
    """
    Generate a transparent CyberGuard risk assessment.

    Parameters:
        url:
            URL being analyzed.

        malicious_probability:
            ML model's estimated probability for malicious class.

        features:
            Dictionary returned by extract_features().

        scheme:
            The supplied URL scheme or "unknown" for a scheme-less URL
            normalized with an HTTP placeholder for the model.
    """

    adjustments = []
    reasons = []
    positive_signals = []

    def add_risk_points(delta, reason):
        adjustments.append({"rule": reason, "delta": delta})
        reasons.append(reason)

    hostname = get_hostname(url)
    try:
        ip_address(hostname.removesuffix("."))
        is_ip_address = True
    except ValueError:
        is_ip_address = False
    root_domain = "" if is_ip_address else get_root_domain(hostname)
    if scheme is None:
        value = str(url).strip().lower()
        scheme = next(
            (name for name in ("http", "https") if value.startswith(name + "://")),
            "unknown",
        )

    # --------------------------------------------------------
    # 1. ML SIGNAL
    # --------------------------------------------------------

    if malicious_probability >= 0.80:

        add_risk_points(30, "ML detector shows a high malicious probability.")

    elif malicious_probability >= 0.60:

        add_risk_points(20, "ML detector shows an elevated malicious probability.")

    elif malicious_probability >= 0.40:

        add_risk_points(10, "ML detector shows some malicious indicators.")

    else:

        positive_signals.append(
            "ML detector shows a relatively low malicious probability."
        )

    # --------------------------------------------------------
    # 2. HTTPS
    # --------------------------------------------------------

    if scheme == "https":

        positive_signals.append(
            "URL uses HTTPS."
        )

    elif scheme == "http":

        add_risk_points(10, "URL does not use HTTPS.")

    # --------------------------------------------------------
    # 3. IP ADDRESS
    # --------------------------------------------------------

    if is_ip_address:

        add_risk_points(25, "URL uses an IP address instead of a normal domain.")

    # --------------------------------------------------------
    # 4. SUSPICIOUS TLD
    # --------------------------------------------------------

    if hostname and not is_ip_address:

        tld = "." + hostname.removesuffix(".").split(".")[-1]

        if tld in SUSPICIOUS_TLDS:

            add_risk_points(15, f"Domain uses a potentially suspicious TLD ({tld}).")

    # --------------------------------------------------------
    # 5. SUSPICIOUS KEYWORDS
    # --------------------------------------------------------

    url_lower = str(url).lower()

    matched_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:

        # Match complete words/tokens rather than substrings.
        #
        # This prevents:
        #     cybersecurity
        #
        # from incorrectly matching:
        #     security
        #
        # while still matching:
        #     cyber-security
        #     /security/login
        #     bank-login.xyz

        pattern = (
            r"(?<![a-z0-9])"
            + re.escape(keyword)
            + r"(?![a-z0-9])"
        )

        if re.search(
            pattern,
            url_lower
        ):

            matched_keywords.append(
                keyword
            )

    if matched_keywords:

        # Maximum 20 points from keywords
        keyword_score = min(
            len(matched_keywords) * 4,
            20
        )

        add_risk_points(
            keyword_score,
            "Suspicious keywords detected: "
            + ", ".join(
                sorted(matched_keywords)
            )
            + ".",
        )

    # --------------------------------------------------------
    # 6. @ SYMBOL
    # --------------------------------------------------------

    if features.get("at_symbol", 0) == 1:

        add_risk_points(20, "URL contains an @ symbol, which can obscure the destination.")

    # --------------------------------------------------------
    # 7. PUNYCODE
    # --------------------------------------------------------

    if features.get("has_punycode", 0) == 1:

        add_risk_points(
            20,
            "Domain contains punycode, which can be associated with "
            "look-alike domains.",
        )

    # --------------------------------------------------------
    # 8. URL ENCODING
    # --------------------------------------------------------

    if features.get("encoded_chars", 0) > 0:

        add_risk_points(5, "URL contains encoded characters.")

    # --------------------------------------------------------
    # 9. MANY SUBDOMAINS
    # --------------------------------------------------------

    if features.get("subdomains", 0) >= 3:

        add_risk_points(10, "URL contains multiple subdomains.")

    # --------------------------------------------------------
    # 10. LONG URL
    # --------------------------------------------------------

    if features.get("url_len", 0) >= 100:

        add_risk_points(10, "URL is unusually long.")

    # --------------------------------------------------------
    # 11. MANY HYPHENS
    # --------------------------------------------------------

    if features.get("domain_hyphens", 0) >= 2:

        add_risk_points(5, "Domain contains multiple hyphens.")

    # --------------------------------------------------------
    # 12. QUERY PARAMETERS
    # --------------------------------------------------------

    if features.get("query_len", 0) >= 50:

        add_risk_points(5, "URL contains a long query string.")

    # --------------------------------------------------------
    # 13. BRAND IMPERSONATION
    # --------------------------------------------------------

    impersonated_brand = None if is_ip_address else detect_brand_impersonation(hostname)

    if impersonated_brand:

        add_risk_points(
            25,
            f"Hostname appears to impersonate "
            f"{impersonated_brand}.",
        )

    # --------------------------------------------------------
    # 14. NESTED URL / REDIRECT DETECTION
    # --------------------------------------------------------

    nested_urls = detect_nested_urls(
        url
    )

    if nested_urls:

        add_risk_points(
            15,
            "URL contains an embedded external URL, "
            "which may indicate a redirect or phishing technique.",
        )

    # --------------------------------------------------------
    # 15. TRUSTED DOMAIN SIGNAL
    # --------------------------------------------------------

    if root_domain in TRUSTED_DOMAINS:

        # Positive signal only.
        # It does not completely override suspicious indicators.
        signal = f"Hostname belongs to a recognized domain ({root_domain})."
        positive_signals.append(signal)
        adjustments.append({"rule": signal, "delta": -25})

    # --------------------------------------------------------
    # 16. KEEP SCORE WITHIN 0-100
    # --------------------------------------------------------

    raw_score = sum(step["delta"] for step in adjustments)
    score = max(0, min(raw_score, 100))
    if raw_score < 0:
        adjustments.append({"rule": "Score floor at 0.", "delta": score - raw_score})
    elif raw_score > 100:
        adjustments.append({"rule": "Score cap at 100.", "delta": score - raw_score})

    # --------------------------------------------------------
    # 17. RISK LEVEL
    # --------------------------------------------------------

    if score >= 60:

        risk_level = "HIGH"

    elif score >= 30:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    # --------------------------------------------------------
    # 18. RECOMMENDATION
    # --------------------------------------------------------

    if risk_level == "HIGH":

        recommendation = (
            "Avoid this URL and do not enter passwords, "
            "financial information, or other sensitive data."
        )

    elif risk_level == "MEDIUM":

        recommendation = (
            "Proceed with caution. Verify the domain and website "
            "before entering sensitive information."
        )

    else:

        recommendation = (
            "No strong risk indicators were detected, but continue "
            "to verify the website before sharing sensitive information."
        )

    # --------------------------------------------------------
    # 19. RETURN RESULT
    # --------------------------------------------------------

    return {
        "url": url,
        "hostname": hostname,
        "risk_score": score,
        "score_breakdown": {
            "starting_score": 0,
            "adjustments": adjustments,
            "final_score": score,
        },
        "risk_level": risk_level,
        "malicious_probability": malicious_probability,
        "reasons": reasons,
        "positive_signals": positive_signals,
        "recommendation": recommendation,
    }
