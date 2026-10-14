import re


# ============================================================
# CYBERGUARD SMS URL EXTRACTOR
# ============================================================


# Explicit HTTP / HTTPS URLs
HTTP_URL_PATTERN = re.compile(
    r"(?i)\bhttps?://[^\s<>\[\]{}\"']+"
)


# WWW URLs
WWW_URL_PATTERN = re.compile(
    r"(?i)(?<![@\w])www\.[a-z0-9-]+(?:\.[a-z0-9-]+)+"
    r"(?:/[^\s<>\[\]{}\"']*)?"
)


# Bare domain URLs
BARE_DOMAIN_PATTERN = re.compile(
    r"(?i)(?<![@\w])"
    r"(?:[a-z0-9-]+\.)+"
    r"[a-z]{2,}"
    r"(?:/[^\s<>\[\]{}\"']*)?"
)


# ============================================================
# CLEAN URL
# ============================================================

def clean_extracted_url(url):
    """
    Remove punctuation commonly surrounding URLs in SMS.
    """

    url = url.strip()

    # Opening punctuation
    url = url.lstrip(
        "([{<\"'"
    )

    # Ending punctuation
    while url and url[-1] in ".,!?;:)]}>\"'":

        url = url[:-1]

    return url


# ============================================================
# VALIDATE URL
# ============================================================

def is_valid_url_candidate(url):
    """
    Basic validation for extracted URL candidates.
    """

    if not url:
        return False

    value = url.lower()

    # Explicit URL
    if value.startswith(
        ("http://", "https://")
    ):
        return True

    # WWW URL
    if value.startswith("www."):
        return True

    # Bare domain
    if "." not in value:
        return False

    # Don't treat email addresses as URLs
    if "@" in value:
        return False

    return True


# ============================================================
# EXTRACT URLS
# ============================================================

def extract_urls(text):
    """
    Extract URLs from an SMS.

    Supports:

        http://example.com
        https://example.com
        www.example.com
        example.com

    Removes duplicate matches caused by overlapping
    URL patterns.
    """

    if text is None:
        return []

    text = str(text)

    candidates = []

    # --------------------------------------------------------
    # 1. Extract HTTP / HTTPS URLs
    # --------------------------------------------------------

    http_matches = list(
        HTTP_URL_PATTERN.finditer(text)
    )

    for match in http_matches:

        candidates.append(
            match.group()
        )

    # --------------------------------------------------------
    # 2. Extract WWW URLs
    # --------------------------------------------------------

    www_matches = list(
        WWW_URL_PATTERN.finditer(text)
    )

    for match in www_matches:

        # Skip if this match is inside an HTTP/HTTPS URL
        overlaps_http = any(
            match.start() >= http.start()
            and match.end() <= http.end()
            for http in http_matches
        )

        if not overlaps_http:

            candidates.append(
                match.group()
            )

    # --------------------------------------------------------
    # 3. Extract bare domains
    # --------------------------------------------------------

    bare_matches = list(
        BARE_DOMAIN_PATTERN.finditer(text)
    )

    for match in bare_matches:

        # Skip if bare-domain match is inside an
        # HTTP/HTTPS URL.
        overlaps_http = any(
            match.start() >= http.start()
            and match.end() <= http.end()
            for http in http_matches
        )

        if overlaps_http:
            continue

        # Skip if it is inside a WWW URL.
        overlaps_www = any(
            match.start() >= www.start()
            and match.end() <= www.end()
            for www in www_matches
        )

        if overlaps_www:
            continue

        candidates.append(
            match.group()
        )

    # --------------------------------------------------------
    # 4. Clean candidates
    # --------------------------------------------------------

    cleaned_urls = []

    for candidate in candidates:

        url = clean_extracted_url(
            candidate
        )

        if not is_valid_url_candidate(
            url
        ):
            continue

        cleaned_urls.append(
            url
        )

    # --------------------------------------------------------
    # 5. Remove duplicates
    # --------------------------------------------------------

    unique_urls = []

    seen = set()

    for url in cleaned_urls:

        key = url.lower()

        if key not in seen:

            seen.add(key)

            unique_urls.append(
                url
            )

    return unique_urls


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_messages = [

        "Visit https://example.com/login",

        "Visit http://evil.xyz/verify.",

        "Visit www.example.com/login",

        "Visit example.com/login",

        "Click https://evil.xyz/login, before your account expires.",

        "Click (https://evil.xyz/login)",

        "Visit http://evil1.xyz or https://evil2.top/verify",

        "Your account is blocked. Visit https://bank.example/login.",

        "Contact support@example.com for help.",

        "No URL in this message.",

        "Visit https://example.com/login twice: "
        "https://example.com/login"
    ]


    print("=" * 70)
    print("CYBERGUARD SMS URL EXTRACTOR TEST")
    print("=" * 70)

    for message in test_messages:

        urls = extract_urls(
            message
        )

        print("\nSMS:")
        print(message)

        print("URLs:")

        if urls:

            for url in urls:

                print(
                    "  ->",
                    url
                )

        else:

            print(
                "  None"
            )