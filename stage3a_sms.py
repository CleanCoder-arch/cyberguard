"""SMS benchmark input validation and deterministic template grouping."""

import csv
import hashlib
import io
import re
import unicodedata
from collections import Counter, defaultdict
from difflib import SequenceMatcher
from pathlib import Path

import pandas as pd

from sms_url_extractor import extract_urls


SMS_GROUPING = {
    "normalization": (
        "NFKC, casefold, word tokens, and slots for links, emails, numbers, and alphanumeric codes"
    ),
    "minimum_fuzzy_length": 24,
    "ngram_size": 3,
    "minimum_length_ratio": 0.80,
    "minimum_ngram_dice": 0.78,
    "minimum_sequence_ratio": 0.87,
    "grouping": "connected components of exact and fuzzy template matches",
}

_EMAIL = re.compile(r"[\w.!#$%&'*+=^`{|}~/-]+@(?:[\w-]+\.)+[\w-]+")
_NUMBER = re.compile(
    r"""(?<!\w)(?:
        (?:\+?\d{1,3}[- .])?(?:\(\d{2,4}\)[- .]?)?\d(?:[- .]?\d){6,14}
        | \d+(?:[.,:/-]\d+)*
        | (?=[a-z0-9]*\d)(?=[a-z0-9]*[a-z])[a-z0-9]{5,}
    )(?!\w)""",
    re.VERBOSE,
)
_WORD = re.compile(r"[^\W_]+")
_SLOT = re.compile(r"\x00(url|email|number)\x00")


def _template(message):
    normalized = unicodedata.normalize("NFKC", message).casefold().replace("\x00", "")
    masked = _EMAIL.sub(" \x00email\x00 ", normalized)
    urls = extract_urls(masked)
    if urls:
        longest_first = sorted(urls, key=lambda url: (-len(url), url))
        alternatives = "|".join(map(re.escape, longest_first))
        masked = re.sub(rf"(?<![\w@.+%-])(?:{alternatives})", " \x00url\x00 ", masked)
    masked = _NUMBER.sub(" \x00number\x00 ", masked)

    parts = _SLOT.split(masked)
    if not any(_WORD.search(part) for part in parts[::2]):
        # Without fixed wording, token masking would merge unrelated messages.
        return normalized, False
    tokens = []
    for index, part in enumerate(parts):
        if index % 2:
            tokens.append(f"<{part}>")
        else:
            tokens.extend(_WORD.findall(part))
    return " ".join(tokens), True


def _fuzzy_pairs(templates):
    minimum_length = SMS_GROUPING["minimum_fuzzy_length"]
    gram_size = SMS_GROUPING["ngram_size"]
    minimum_length_ratio = SMS_GROUPING["minimum_length_ratio"]
    minimum_dice = SMS_GROUPING["minimum_ngram_dice"]
    minimum_sequence = SMS_GROUPING["minimum_sequence_ratio"]
    postings = defaultdict(list)
    gram_counts = []

    for index, current in enumerate(templates):
        grams = {current[start:start + gram_size] for start in range(len(current) - gram_size + 1)}
        gram_counts.append(len(grams))
        if len(current) < minimum_length:
            continue
        # Only pairs sharing a gram can reach the Dice cutoff.
        common = Counter(previous for gram in grams for previous in postings[gram])
        for previous, count in common.items():
            if 2 * count < minimum_dice * (len(grams) + gram_counts[previous]):
                continue
            other = templates[previous]
            if min(len(current), len(other)) < minimum_length_ratio * max(len(current), len(other)):
                continue
            if SequenceMatcher(None, other, current, autojunk=False).ratio() >= minimum_sequence:
                yield other, current
        for gram in grams:
            postings[gram].append(index)


def _digest(message):
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


def sms_group_ids(messages):
    """Return an order-independent group ID for each app-preprocessed message."""
    messages = list(messages)
    unique = sorted(set(messages))
    parents = list(range(len(unique)))

    def root(index):
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def merge(left, right):
        first, second = sorted((root(left), root(right)))
        parents[second] = first

    representative = {}
    for index, message in enumerate(unique):
        key = _template(message)
        first = representative.setdefault(key, index)
        merge(first, index)

    fuzzy_templates = sorted(template for template, fuzzy in representative if fuzzy)
    for first, second in _fuzzy_pairs(fuzzy_templates):
        merge(representative[(first, True)], representative[(second, True)])

    group_ids = {
        message: f"sms-{_digest(unique[root(index)])[:24]}"
        for index, message in enumerate(unique)
    }
    return [group_ids[message] for message in messages]


def load_sms(path):
    """Read a raw v1/v2 or prepared label/text CSV, retaining valid duplicates."""
    source = Path(path).read_bytes()
    try:
        contents = source.decode("utf-8-sig")
    except UnicodeDecodeError:
        contents = source.decode("latin-1")
    reader = csv.reader(io.StringIO(contents, newline=""), strict=True)
    header = next(reader, [])
    if {"v1", "v2"}.issubset(header):
        label_field, message_field = "v1", "v2"
        labels = {"ham": 0, "spam": 1}
    elif {"label", "text"}.issubset(header):
        label_field, message_field = "label", "text"
        labels = {"0": 0, "1": 1}
    else:
        raise ValueError(f"{path} must contain SMS columns v1/v2 or label/text")
    label_column = header.index(label_field)
    message_column = header.index(message_field)

    valid = []
    excluded = []
    for row_id, fields in enumerate(reader, start=1):
        label = fields[label_column].strip().casefold() if label_column < len(fields) else ""
        # Match the app's model input, while keeping template normalization separate.
        message = fields[message_column].strip() if message_column < len(fields) else ""
        reasons = []
        if not label:
            reasons.append("missing_label")
        elif label not in labels:
            reasons.append("invalid_label")
        if not message:
            reasons.append("empty_text")
        if reasons:
            excluded.append((row_id, ";".join(reasons)))
        else:
            valid.append((row_id, message, labels[label], _digest(message)))

    rows = pd.DataFrame(valid, columns=["row_id", "text", "label", "duplicate_key"])
    rows["group_id"] = sms_group_ids(rows["text"])
    exclusions = pd.DataFrame(excluded, columns=["row_id", "reason"])
    return rows, exclusions
