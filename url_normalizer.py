from urllib.parse import urlparse, urlunparse


# ============================================================
# CYBERGUARD URL NORMALIZER
# ============================================================

def normalize_url(url):
    """
    Normalize a URL while preserving security-relevant information.

    Important:
    - Explicit HTTP/HTTPS schemes are preserved.
    - If no scheme is provided, HTTP is used only as a
      parsing placeholder.
    - Hostname is converted to lowercase.
    - Trailing punctuation is removed.
    """

    if url is None:
        raise ValueError("URL cannot be None")

    url = str(url).strip()

    if not url:
        raise ValueError("URL cannot be empty")

    # --------------------------------------------------------
    # Remove surrounding quotes
    # --------------------------------------------------------

    url = url.strip("\"'")

    # --------------------------------------------------------
    # Remove common sentence punctuation
    # --------------------------------------------------------

    while url and url[-1] in ".,;:!?)]}>":
        url = url[:-1]

    if not url:
        raise ValueError("URL became empty after normalization")

    # --------------------------------------------------------
    # Detect whether the user explicitly provided a scheme
    # --------------------------------------------------------

    parsed_initial = urlparse(url)

    has_explicit_scheme = parsed_initial.scheme.lower() in (
        "http",
        "https"
    )

    # --------------------------------------------------------
    # Add HTTP only as a parsing placeholder
    # --------------------------------------------------------

    if not has_explicit_scheme:

        url_for_parsing = "http://" + url

    else:

        url_for_parsing = url

    # --------------------------------------------------------
    # Parse URL
    # --------------------------------------------------------

    parsed = urlparse(url_for_parsing)

    scheme = parsed.scheme.lower()

    if scheme not in ("http", "https"):

        raise ValueError(
            f"Unsupported URL scheme: {parsed.scheme}"
        )

    # --------------------------------------------------------
    # Validate hostname
    # --------------------------------------------------------

    hostname = parsed.hostname

    if not hostname:

        raise ValueError(
            "Invalid URL: hostname could not be determined"
        )

    hostname = hostname.lower()

    # --------------------------------------------------------
    # Preserve userinfo if present
    # --------------------------------------------------------

    netloc = ""

    if parsed.username is not None:

        netloc += parsed.username

        if parsed.password is not None:

            netloc += ":" + parsed.password

        netloc += "@"

    netloc += hostname

    # --------------------------------------------------------
    # Preserve port
    # --------------------------------------------------------

    try:

        if parsed.port is not None:

            netloc += ":" + str(parsed.port)

    except ValueError:

        raise ValueError(
            "Invalid URL: invalid port"
        )

    # --------------------------------------------------------
    # Reconstruct normalized URL
    # --------------------------------------------------------

    normalized = urlunparse(
        (
            scheme,
            netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment
        )
    )

    return normalized, has_explicit_scheme


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_urls = [

        "https://Google.com",

        "HTTPS://WWW.GOOGLE.COM/",

        "google.com",

        "www.microsoft.com",

        "https://example.com...",

        "   https://github.com   ",

        "http://secure-login-bank.xyz/verify"
    ]

    print("=" * 70)
    print("CYBERGUARD URL NORMALIZER TEST")
    print("=" * 70)

    for url in test_urls:

        try:

            normalized, explicit_scheme = normalize_url(url)

            print("\nInput:           ", url)
            print("Normalized:      ", normalized)
            print("Explicit Scheme: ", explicit_scheme)

        except ValueError as e:

            print("\nInput:  ", url)
            print("ERROR:  ", e)