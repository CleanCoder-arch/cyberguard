import re
from ipaddress import IPv4Address, IPv6Address
from urllib.parse import urlsplit


SCHEME_PREFIX = re.compile(r"^([a-z][a-z0-9+.-]*):", re.IGNORECASE | re.ASCII)
HOST_WITH_PORT = re.compile(r"(\[[^\[\]]+\]|[^:\[\]]+)(?::([0-9]+))?")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.IGNORECASE | re.ASCII)


class URLValidationError(ValueError):
    """The supplied text cannot be scanned as an HTTP or HTTPS URL."""


def normalize_host(host):
    if host.startswith("["):
        address = host[1:-1]
        literal, separator, zone = address.partition("%")
        if separator and not re.fullmatch(r"25[A-Za-z0-9._~-]+", zone):
            raise URLValidationError("Invalid URL: invalid IPv6 zone identifier.")
        try:
            IPv6Address(literal)
        except ValueError as error:
            raise URLValidationError("Invalid URL: invalid IPv6 address.") from error
        return f"[{literal.lower()}{separator}{zone}]"

    try:
        ascii_host = host.encode("idna").decode("ascii").removesuffix(".")
    except UnicodeError as error:
        raise URLValidationError("Invalid URL: invalid hostname.") from error

    labels = ascii_host.split(".")
    if len(ascii_host) > 253 or any(not DNS_LABEL.fullmatch(label) for label in labels):
        raise URLValidationError("Invalid URL: invalid hostname.")

    # A trailing numeric DNS label would be parsed as an IPv4 address by browsers.
    if labels[-1].isdigit() or re.fullmatch(r"0x[0-9a-f]+", labels[-1], re.IGNORECASE):
        try:
            IPv4Address(ascii_host)
        except ValueError as error:
            raise URLValidationError("Invalid URL: invalid IPv4 address.") from error
    return host.lower()


def normalize_url(url):
    """Validate a URL and return the model input and whether its scheme was supplied."""
    if url is None:
        raise URLValidationError("URL cannot be None.")

    url = str(url).strip()
    if len(url) >= 2 and url[0] in "\"'" and url[-1] == url[0]:
        url = url[1:-1]
    if not url:
        raise URLValidationError("URL cannot be empty.")
    if any(char.isspace() or not char.isprintable() or char == "\\" for char in url):
        raise URLValidationError("Invalid URL: whitespace, controls and backslashes are not allowed.")

    # A dotted hostname or localhost can be supplied with a port and no scheme.
    # Other single-label hosts with ports need an explicit scheme or leading "//".
    match = SCHEME_PREFIX.match(url)
    explicit_scheme = False
    if match:
        scheme = match[1].lower()
        remainder = url[match.end():]
        if scheme in {"http", "https"}:
            if not remainder.startswith("//"):
                raise URLValidationError("Invalid URL: HTTP and HTTPS require '://'.")
            explicit_scheme = True
        elif remainder.startswith("//") or ("." not in scheme and scheme != "localhost"):
            raise URLValidationError(f"Unsupported URL scheme: {scheme}.")

    if not explicit_scheme:
        url = "http://" + url.removeprefix("//")

    try:
        parsed = urlsplit(url)
    except ValueError as error:
        raise URLValidationError("Invalid URL: invalid hostname or IPv6 address.") from error

    userinfo, separator, authority = parsed.netloc.rpartition("@")
    if separator and (not explicit_scheme or "@" in userinfo):
        raise URLValidationError("Invalid URL: invalid user information in the hostname.")

    authority_match = HOST_WITH_PORT.fullmatch(authority)
    if authority_match is None:
        raise URLValidationError("Invalid URL: invalid hostname or port. Enclose IPv6 addresses in brackets.")

    host, port = authority_match.groups()
    host = normalize_host(host)

    # Retain port normalization used by the fitted model.
    if port is not None:
        port_digits = port.lstrip("0") or "0"
        if len(port_digits) > 5 or not 1 <= int(port_digits) <= 65535:
            raise URLValidationError("Invalid URL: port must be between 1 and 65535.")
        host += ":" + port_digits

    # Preserve the spelling of the path, query and fragment, including delimiters.
    authority_end = url.index("://") + 3 + len(parsed.netloc)
    return f"{parsed.scheme}://{userinfo}{separator}{host}{url[authority_end:]}", explicit_scheme


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
