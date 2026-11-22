"""Dataset validation and registrable-domain grouping for the URL benchmark."""

from functools import lru_cache
from hashlib import sha256
from importlib.resources import files
from ipaddress import ip_address
from urllib.parse import urlsplit

import pandas as pd
import tldextract

from url_normalizer import URLValidationError, normalize_url


_DOMAIN_EXTRACTOR = tldextract.TLDExtract(
    cache_dir=None,
    suffix_list_urls=(),
    include_psl_private_domains=True,
)
URL_GROUPING = {
    "method": "registrable domain using the Public Suffix List",
    "tldextract_version": tldextract.__version__,
    "suffix_snapshot_sha256": sha256(
        files("tldextract").joinpath(".tld_set_snapshot").read_bytes()
    ).hexdigest(),
    "include_private_suffixes": True,
    "unlisted_suffix": "PSL prevailing wildcard rule",
    "ip_literals": "canonical IP address without a zone identifier",
    "duplicate_key": "SHA-256 of the app-normalized URL",
}


def canonical_hostname(hostname):
    """Use ASCII DNS spelling or the canonical spelling of an IP address."""
    hostname = hostname.lower().removesuffix(".")
    try:
        return str(ip_address(hostname.partition("%")[0]))
    except ValueError:
        return hostname.encode("idna").decode("ascii").removesuffix(".")


@lru_cache(maxsize=65536)
def _registrable_group(hostname):
    try:
        return str(ip_address(hostname))
    except ValueError:
        domain = _DOMAIN_EXTRACTOR(hostname)

    if domain.suffix:
        # A URL may use a public suffix itself as its hostname.
        return domain.top_domain_under_public_suffix or hostname

    # The PSL applies an implicit wildcard to hostnames without a matching rule.
    return ".".join(hostname.rsplit(".", 2)[-2:])


def registrable_group(hostname):
    return _registrable_group(canonical_hostname(hostname))


def load_urls(path):
    """Load raw or prepared URLs, retaining each accepted source row and its group."""
    header = pd.read_csv(path, nrows=0).columns
    if {"URL", "Label"}.issubset(header):
        url_column, label_column = "URL", "Label"
        labels = {"good": 0, "bad": 1}
    elif {"url", "label"}.issubset(header):
        url_column, label_column = "url", "label"
        labels = {"0": 0, "1": 1}
    else:
        raise ValueError(f"{path} must contain URL/Label or url/label columns")

    source = pd.read_csv(
        path,
        usecols=[url_column, label_column],
        dtype=str,
        keep_default_na=False,
        skip_blank_lines=False,
    )
    rows, exclusions = [], []
    for row_id, (value, raw_label) in enumerate(
        source[[url_column, label_column]].itertuples(index=False, name=None), start=1
    ):
        raw_label = raw_label.strip()
        if raw_label not in labels:
            reason = "unsupported URL label" if raw_label else "missing URL label"
            exclusions.append((row_id, reason))
            continue

        try:
            url, _ = normalize_url(value)
        except URLValidationError as error:
            exclusions.append((row_id, str(error)))
            continue

        hostname = canonical_hostname(urlsplit(url).hostname)
        duplicate_key = sha256(url.encode("utf-8")).hexdigest()
        rows.append((
            row_id, url, labels[raw_label], _registrable_group(hostname), hostname, duplicate_key,
        ))

    return (
        pd.DataFrame(
            rows, columns=["row_id", "url", "label", "group_id", "hostname", "duplicate_key"]
        ),
        pd.DataFrame(exclusions, columns=["row_id", "reason"]),
    )
