import re
from urllib.parse import urlparse
import tldextract
import math


# ============================================
# TLD EXTRACTOR
# ============================================

# Use the locally available suffix list.
# This prevents tldextract from making
# network requests.
_ext = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None
)


# ============================================
# SUSPICIOUS WORDS
# ============================================

SUSPICIOUS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "bank",
    "confirm",
    "password",
    "free",
    "gift",
    "bonus",
    "signin",
    "wallet",
    "kyc"
]


# ============================================
# URL SHORTENERS
# ============================================

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "cutt.ly"
]


# ============================================
# IP ADDRESS PATTERN
# ============================================

IP_RE = re.compile(
    r"^\d{1,3}(\.\d{1,3}){3}$"
)


def calculate_entropy(text):
    """
    Calculate Shannon entropy of a string.
    Higher entropy can indicate random-looking domains.
    """

    if not text:
        return 0.0

    frequency = {}

    for char in text:
        frequency[char] = frequency.get(char, 0) + 1

    entropy = 0.0

    for count in frequency.values():

        probability = count / len(text)

        entropy -= probability * math.log2(
            probability
        )

    return entropy


def count_vowels(text):
    """
    Count vowels in a string.
    """

    return sum(
        char in "aeiou"
        for char in text.lower()
    )


def count_consonants(text):
    """
    Count alphabetic consonants.
    """

    return sum(
        char.isalpha() and char not in "aeiou"
        for char in text.lower()
    )


# ============================================
# FEATURE EXTRACTION FUNCTION
# ============================================

def extract_features(url):
    """
    Convert a URL into numerical security features.
    """

    # ----------------------------------------
    # Clean input
    # ----------------------------------------

    url = str(url).strip()

    # Lowercase version used for keyword checks.
    lower_url = url.lower()

    # ----------------------------------------
    # Prepare URL for parsing
    # ----------------------------------------

    if "://" in url:
        url_for_parse = url
    else:
        url_for_parse = "http://" + url

    # ----------------------------------------
    # Parse URL safely
    # ----------------------------------------

    try:

        parsed_url = urlparse(url_for_parse)

        host = parsed_url.netloc.lower().split(":")[0]

    except ValueError:

        # Some datasets contain malformed URLs,
        # especially malformed IPv6-style URLs.
        #
        # Remove square brackets and try again.

        safe_url = (
            url_for_parse
            .replace("[", "")
            .replace("]", "")
        )

        try:

            parsed_url = urlparse(safe_url)

            host = parsed_url.netloc.lower().split(":")[0]

        except ValueError:

            # Final fallback.
            #
            # We don't want one malformed URL
            # to stop the entire ML training process.

            parsed_url = urlparse(
                "http://invalid.local"
            )

            host = ""

    # ----------------------------------------
    # Extract domain information
    # ----------------------------------------

    try:

        extracted = _ext(url)

    except Exception:

        # If tldextract encounters a malformed
        # URL, use empty domain components.

        extracted = _ext("")

    # ----------------------------------------
    # Count digits
    # ----------------------------------------

    digits = sum(
        character.isdigit()
        for character in url
    )

    # ----------------------------------------
    # Suspicious words
    # ----------------------------------------

    suspicious_count = sum(
        word in lower_url
        for word in SUSPICIOUS
    )

    # ----------------------------------------
    # URL shortener detection
    # ----------------------------------------

    shortener_found = (
    host in SHORTENERS
)

    # ----------------------------------------
    # Subdomain count
    # ----------------------------------------

    subdomain_parts = [
        part
        for part in extracted.subdomain.split(".")
        if part
    ]

    # ----------------------------------------
    # Return features
    # ----------------------------------------

    return {

        "domain_entropy": calculate_entropy(host),

"domain_digits": sum(
    char.isdigit()
    for char in host
),

"domain_digit_ratio": (
    sum(char.isdigit() for char in host)
    / max(len(host), 1)
),

"domain_vowels": count_vowels(host),

"domain_consonants": count_consonants(host),

"domain_special_chars": len(
    re.findall(
        r"[^a-zA-Z0-9.-]",
        host
    )
),

"query_len": len(
    parsed_url.query
),

"fragment_len": len(
    parsed_url.fragment
),

"path_depth": len([
    part
    for part in parsed_url.path.split("/")
    if part
]),

"has_query": int(
    bool(parsed_url.query)
),

"has_fragment": int(
    bool(parsed_url.fragment)
),

"has_punycode": int(
    "xn--" in host
),

"encoded_chars": len(
    re.findall(
        r"%[0-9a-fA-F]{2}",
        url
    )
),

"exclamation": url.count("!"),

"question_mark": url.count("?"),

"equals": url.count("="),

        # Basic URL characteristics
        "url_len": len(url),

        "host_len": len(host),

        "path_len": len(
            parsed_url.path
        ),

        # Character counts
        "dots": url.count("."),

        "hyphens_host": host.count("-"),

        "digits": digits,

        "digit_ratio": (
            digits / max(len(url), 1)
        ),

        # Security indicators
        "at_symbol": int(
            "@" in url
        ),

        "has_ip": int(
            bool(IP_RE.match(host))
        ),

        "https": int(
            parsed_url.scheme == "https"
        ),

        # Domain structure
        "subdomains": len(
            subdomain_parts
        ),

        # Suspicious words
        "susp_words": suspicious_count,

        # URL shortener
        "shortener": int(
            shortener_found
        ),

        # Multiple // occurrences
        "double_slash": int(
            url.count("//") > 1
        ),

        # Special characters
        "special_chars": len(
            re.findall(
                r"[?=&%_~]",
                url
            )
        ),

        # Domain suffix length
        "suffix_len": len(
            extracted.suffix
        )

        
    }


# ============================================
# TEST
# ============================================

if __name__ == "__main__":

    test_url = (
        "http://secure-login-bank.xyz/verify"
    )

    features = extract_features(
        test_url
    )

    print("URL:")
    print(test_url)

    print("\nExtracted Features:")

    for name, value in features.items():

        print(
            f"{name}: {value}"
        )