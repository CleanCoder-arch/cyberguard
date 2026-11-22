import re


_SCHEME = r"(?ai:[a-z][a-z0-9+.-]*://)"
_URL_TAIL = r"""[^\s<>{}"']*"""
_DOMAIN = r"(?ai:(?:[a-z0-9-]+\.)+(?:xn--[a-z0-9-]+|[a-z]{2,}))"
_IP_LITERAL = r"(?:[0-9]+\.){3}[0-9]+|\[(?ai:[0-9a-f.]*):[^\s\[\]<>]*\]"
_BARE_HOST = rf"(?:{_DOMAIN}|{_IP_LITERAL})(?![\w@+%-]|\.[\w.-])"
_BARE_PORT = r"""(?::[^\s/?#()<>\[\]{}"',;!]*)?"""
_BARE_AUTHORITY = rf"(?<![\w@.+%-]){_BARE_HOST}{_BARE_PORT}"
_EMAIL_ATOM = r"""[\w.!#$%&'*+=^_`{|}~/-]"""
_EMAIL_LOCAL = rf"""(?:{_EMAIL_ATOM}+|"[^"\r\n]+")"""
_EMAIL_DOMAIN = r"(?:[\w-]+(?:\.[\w-]+)+|\[[^\s\[\]]+\])"

# Consume email addresses as a whole so neither the local part nor a
# subdomain of the address can be mistaken for a standalone link.
_CANDIDATE = re.compile(
    rf"(?P<explicit>(?<![\w@]){_SCHEME}{_URL_TAIL})"
    rf"|(?P<bare_with_suffix>{_BARE_AUTHORITY}[/?#]{_URL_TAIL})"
    rf"|(?<!{_EMAIL_ATOM})(?ai:mailto:)?{_EMAIL_LOCAL}@{_EMAIL_DOMAIN}"
    rf"|(?P<bare>{_BARE_AUTHORITY})"
)
_URL_PARTS = re.compile(rf"^({_SCHEME})?([^/?#]*)(.*)$")
_URL_WRAPPERS = {"<": ">", '"': '"', "'": "'"}


def clean_extracted_url(url, opener=None):
    """Remove common sentence delimiters, keeping balanced URL brackets."""
    url = url.rstrip(".,")
    closing_pairs = {")": "("}
    if opener == "[":
        closing_pairs["]"] = "["

    if url and url[-1] in closing_pairs:
        unmatched = {
            close: url.count(close) - url.count(opening)
            for close, opening in closing_pairs.items()
        }
        end = len(url)
        while end and unmatched.get(url[end - 1], 0) > 0:
            unmatched[url[end - 1]] -= 1
            end -= 1
        url = url[:end]
    scheme, authority, suffix = _URL_PARTS.fullmatch(url).groups()
    if not suffix:
        # With no path or query, these characters are sentence punctuation.
        authority = authority.rstrip("!;")
    return (scheme or "") + authority + suffix


def _duplicate_key(url):
    """Fold case only in the scheme and the hostname."""
    scheme, authority, suffix = _URL_PARTS.fullmatch(url).groups()
    userinfo, separator, host_and_port = authority.rpartition("@")
    if host_and_port.startswith("[") and "]" in host_and_port:
        host, closer, port = host_and_port.partition("]")
        address, zone_separator, zone = host.partition("%")
        host_and_port = address.lower() + zone_separator + zone + closer + port
    else:
        host, colon, port = host_and_port.partition(":")
        host_and_port = host.lower() + colon + port
    return (scheme or "").lower(), userinfo, separator, host_and_port, suffix


def extract_urls(text):
    """Return distinct web link candidates in their order of appearance."""
    if text is None:
        return []

    text = str(text)
    seen = set()
    urls = []
    for match in _CANDIDATE.finditer(text):
        candidate = (
            match.group("explicit") or match.group("bare_with_suffix") or match.group("bare")
        )
        if candidate is None:
            continue

        start, end = match.span()
        opener = text[start - 1] if start else None
        if _URL_WRAPPERS.get(opener) == text[end:end + 1]:
            url = candidate
        else:
            url = clean_extracted_url(candidate, opener)
        key = _duplicate_key(url)
        if key not in seen:
            seen.add(key)
            urls.append(url)
    return urls


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
