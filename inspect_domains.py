import pandas as pd
from urllib.parse import urlparse


def extract_host(url):
    """
    Safely extract hostname from a URL.
    Returns an empty string if the URL is malformed.
    """

    try:
        url = str(url).strip()

        if not url:
            return ""

        # Add scheme if missing
        if "://" not in url:
            url = "http://" + url

        parsed = urlparse(url)

        host = parsed.hostname

        if host is None:
            return ""

        host = host.lower()

        # Remove www.
        if host.startswith("www."):
            host = host[4:]

        return host

    except (ValueError, TypeError):
        return ""


print("=" * 60)
print("CYBERGUARD DOMAIN DATASET INSPECTION")
print("=" * 60)

print("\nLoading dataset...")

df = pd.read_csv("data/urls.csv")

print(f"Total rows: {len(df)}")

# Normalize URL
df["url"] = df["url"].astype(str).str.strip()

print("\nExtracting hosts safely...")

df["host"] = df["url"].apply(extract_host)

# Count malformed URLs
invalid_count = (df["host"] == "").sum()

print(f"Valid hosts   : {len(df) - invalid_count}")
print(f"Invalid hosts : {invalid_count}")


# ---------------------------------------------------------
# CHECK SPECIFIC DOMAINS
# ---------------------------------------------------------

test_domains = [
    "google.com",
    "github.com",
    "microsoft.com",
    "amazon.com",
    "example.com",
]

print("\n" + "=" * 60)
print("KNOWN DOMAIN INSPECTION")
print("=" * 60)

for domain in test_domains:

    print(f"\n=== {domain} ===")

    matches = df[df["host"] == domain]

    print(f"Total exact-host matches: {len(matches)}")

    if len(matches) == 0:
        print("No exact-host entries found.")
        continue

    print("\nLabel distribution:")

    print(
        matches["label"]
        .value_counts()
        .sort_index()
        .to_string()
    )

    print("\nFirst 10 matching URLs:")

    print(
        matches[["url", "label"]]
        .head(10)
        .to_string(index=False)
    )


# ---------------------------------------------------------
# TOP DOMAINS BY LABEL
# ---------------------------------------------------------

print("\n" + "=" * 60)
print("TOP HOSTS BY LABEL")
print("=" * 60)

domain_counts = (
    df[df["host"] != ""]
    .groupby(["host", "label"])
    .size()
    .sort_values(ascending=False)
    .head(30)
)

print(domain_counts.to_string())


# ---------------------------------------------------------
# INVALID URL EXAMPLES
# ---------------------------------------------------------

if invalid_count > 0:

    print("\n" + "=" * 60)
    print("INVALID URL EXAMPLES")
    print("=" * 60)

    invalid_urls = df[df["host"] == ""]["url"].head(20)

    for i, url in enumerate(invalid_urls, start=1):
        print(f"{i}. {url}")


print("\n" + "=" * 60)
print("INSPECTION COMPLETE")
print("=" * 60)