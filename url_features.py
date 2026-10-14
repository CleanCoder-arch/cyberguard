import re
import math
from collections import Counter
from urllib.parse import urlparse


# ============================================================
# COMMON SUSPICIOUS WORDS
# ============================================================

SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "bank",
    "payment",
    "confirm",
    "password",
    "credential",
    "authorize",
    "authentication",
    "wallet",
    "billing",
    "recover",
    "unlock",
    "suspend",
    "limited",
    "alert",
    "bonus",
    "free",
    "claim",
]


# ============================================================
# URL SHORTENING SERVICES
# ============================================================

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "cutt.ly",
    "rb.gy",
}


# ============================================================
# COMMON TLDs
# ============================================================

COMMON_TLDS = {
    "com",
    "org",
    "net",
    "edu",
    "gov",
    "in",
    "co",
    "uk",
    "de",
    "fr",
    "au",
    "ca",
    "jp",
}


# ============================================================
# ENTROPY
# ============================================================

def calculate_entropy(text):
    """
    Calculate Shannon entropy of a string.
    """

    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


# ============================================================
# SAFE URL PARSING
# ============================================================

def safe_parse_url(url):
    """
    Safely parse a URL.

    Handles malformed URLs without crashing the
    complete training process.
    """

    try:
        url = str(url).strip()

        if not url:
            return None

        # Add scheme if missing
        if "://" not in url:
            url = "http://" + url

        return urlparse(url)

    except Exception:
        return None


# ============================================================
# HOST EXTRACTION
# ============================================================

def extract_host(url):
    """
    Safely extract hostname.
    """

    parsed = safe_parse_url(url)

    if parsed is None:
        return ""

    try:
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


# ============================================================
# DOMAIN FEATURES
# ============================================================

def extract_domain_features(host):
    """
    Extract additional domain-level features.
    """

    if not host:
        return {
            "domain_entropy": 0.0,
            "domain_digits": 0,
            "domain_digit_ratio": 0.0,
            "domain_vowels": 0,
            "domain_consonants": 0,
            "domain_special_chars": 0,
            "domain_len": 0,
            "domain_parts": 0,
        }

    # Remove www.
    domain = host.removeprefix("www.")

    letters = sum(c.isalpha() for c in domain)
    digits = sum(c.isdigit() for c in domain)

    vowels = sum(
        c in "aeiou"
        for c in domain.lower()
    )

    consonants = sum(
        c.isalpha() and c not in "aeiou"
        for c in domain.lower()
    )

    special_chars = sum(
        not c.isalnum() and c not in ".-"
        for c in domain
    )

    return {
        "domain_entropy": calculate_entropy(domain),
        "domain_digits": digits,
        "domain_digit_ratio": (
            digits / len(domain)
            if len(domain) > 0 else 0.0
        ),
        "domain_vowels": vowels,
        "domain_consonants": consonants,
        "domain_special_chars": special_chars,

        # New features
        "domain_len": len(domain),
        "domain_parts": len(
            [p for p in domain.split(".") if p]
        ),
    }


# ============================================================
# MAIN FEATURE EXTRACTION
# ============================================================

def extract_features(url):

    url = str(url).strip()

    parsed_url = safe_parse_url(url)

    # --------------------------------------------------------
    # Fallback for malformed URLs
    # --------------------------------------------------------

    if parsed_url is None:

        return {
            "domain_entropy": 0.0,
            "domain_digits": 0,
            "domain_digit_ratio": 0.0,
            "domain_vowels": 0,
            "domain_consonants": 0,
            "domain_special_chars": 0,

            "query_len": 0,
            "fragment_len": 0,
            "path_depth": 0,
            "has_query": 0,
            "has_fragment": 0,
            "has_punycode": 0,
            "encoded_chars": 0,
            "exclamation": 0,
            "question_mark": 0,
            "equals": 0,

            "url_len": len(url),
            "host_len": 0,
            "path_len": 0,
            "dots": url.count("."),
            "hyphens_host": 0,
            "digits": sum(c.isdigit() for c in url),

            "digit_ratio": (
                sum(c.isdigit() for c in url) / len(url)
                if url else 0.0
            ),

            "at_symbol": int("@" in url),
            "has_ip": 0,
            "https": int(url.lower().startswith("https")),
            "subdomains": 0,
            "susp_words": 0,
            "shortener": 0,
            "double_slash": int("//" in url[8:]),
            "special_chars": sum(
                not c.isalnum() and c not in "/:.-_?"
                for c in url
            ),
            "suffix_len": 0,

            # New features
            "domain_len": 0,
            "domain_parts": 0,
            "tld_len": 0,
            "is_common_tld": 0,
            "has_www": 0,
            "path_digits": 0,
            "query_digits": 0,
            "domain_hyphens": 0,
        }

    # --------------------------------------------------------
    # Basic components
    # --------------------------------------------------------

    host = parsed_url.hostname or ""
    host = host.lower()

    path = parsed_url.path or ""
    query = parsed_url.query or ""
    fragment = parsed_url.fragment or ""

    # Remove www for domain-level calculations
    clean_domain = host.removeprefix("www.")

    # --------------------------------------------------------
    # Domain features
    # --------------------------------------------------------

    domain_features = extract_domain_features(host)

    # --------------------------------------------------------
    # TLD
    # --------------------------------------------------------

    if "." in clean_domain:

        tld = clean_domain.rsplit(".", 1)[-1].lower()

    else:

        tld = ""

    tld_len = len(tld)

    is_common_tld = int(
        tld in COMMON_TLDS
    )

    # --------------------------------------------------------
    # URL statistics
    # --------------------------------------------------------

    url_len = len(url)

    digits = sum(
        c.isdigit()
        for c in url
    )

    digit_ratio = (
        digits / url_len
        if url_len > 0
        else 0.0
    )

    # --------------------------------------------------------
    # Suspicious words
    # --------------------------------------------------------

    url_lower = url.lower()

    suspicious_word_count = sum(
        word in url_lower
        for word in SUSPICIOUS_WORDS
    )

    # --------------------------------------------------------
    # Shortener
    # --------------------------------------------------------

    shortener = int(
        host in SHORTENER_DOMAINS
    )

    # --------------------------------------------------------
    # IP address detection
    # --------------------------------------------------------

    ipv4_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    has_ip = int(
        bool(re.match(ipv4_pattern, host))
    )

    # --------------------------------------------------------
    # Subdomains
    # --------------------------------------------------------

    domain_parts = [
        p for p in clean_domain.split(".")
        if p
    ]

    subdomains = max(
        len(domain_parts) - 2,
        0
    )

    # --------------------------------------------------------
    # Path depth
    # --------------------------------------------------------

    path_parts = [
        p for p in path.split("/")
        if p
    ]

    path_depth = len(path_parts)

    # --------------------------------------------------------
    # Encoded characters
    # --------------------------------------------------------

    encoded_chars = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            url
        )
    )

    # --------------------------------------------------------
    # Special characters
    # --------------------------------------------------------

    special_chars = sum(
        not c.isalnum()
        and c not in "/:.-_?"
        for c in url
    )

    # --------------------------------------------------------
    # Suffix
    # --------------------------------------------------------

    suffix_len = len(
        parsed_url.path.rsplit(".", 1)[-1]
    ) if "." in parsed_url.path else 0

    # ========================================================
    # RETURN FEATURES
    # ========================================================

    features = {

        # ------------------------------
        # Existing domain features
        # ------------------------------

        "domain_entropy":
            domain_features["domain_entropy"],

        "domain_digits":
            domain_features["domain_digits"],

        "domain_digit_ratio":
            domain_features["domain_digit_ratio"],

        "domain_vowels":
            domain_features["domain_vowels"],

        "domain_consonants":
            domain_features["domain_consonants"],

        "domain_special_chars":
            domain_features["domain_special_chars"],

        # ------------------------------
        # Existing URL features
        # ------------------------------

        "query_len":
            len(query),

        "fragment_len":
            len(fragment),

        "path_depth":
            path_depth,

        "has_query":
            int(bool(query)),

        "has_fragment":
            int(bool(fragment)),

        "has_punycode":
            int("xn--" in host),

        "encoded_chars":
            encoded_chars,

        "exclamation":
            url.count("!"),

        "question_mark":
            url.count("?"),

        "equals":
            url.count("="),

        "url_len":
            url_len,

        "host_len":
            len(host),

        "path_len":
            len(path),

        "dots":
            host.count("."),

        "hyphens_host":
            host.count("-"),

        "digits":
            digits,

        "digit_ratio":
            digit_ratio,

        "at_symbol":
            int("@" in url),

        "has_ip":
            has_ip,

        "https":
            int(parsed_url.scheme.lower() == "https"),

        "subdomains":
            subdomains,

        "susp_words":
            suspicious_word_count,

        "shortener":
            shortener,

        "double_slash":
            int("//" in url[8:]),

        "special_chars":
            special_chars,

        "suffix_len":
            suffix_len,

        # ------------------------------
        # NEW DOMAIN FEATURES
        # ------------------------------

        "domain_len":
            domain_features["domain_len"],

        "domain_parts":
            domain_features["domain_parts"],

        "tld_len":
            tld_len,

        "is_common_tld":
            is_common_tld,

        "has_www":
            int(host.startswith("www.")),

        "path_digits":
            sum(c.isdigit() for c in path),

        "query_digits":
            sum(c.isdigit() for c in query),

        "domain_hyphens":
            clean_domain.count("-"),
    }

    return features


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_url = (
        "http://secure-login-bank.xyz/verify"
    )

    print("URL:")
    print(test_url)

    print("\nExtracted Features:")

    features = extract_features(test_url)

    for name, value in features.items():

        print(
            f"{name}: {value}"
        )

    print(
        f"\nTotal features: {len(features)}"
    )