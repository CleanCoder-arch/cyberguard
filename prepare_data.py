import pandas as pd


# ============================================
# 1. PREPARE URL DATASET
# ============================================

print("Preparing URL dataset...")

# Load raw URL dataset
urls = pd.read_csv("data/raw_urls.csv")

# Keep only the columns we need
urls = urls[["URL", "Label"]]

# Rename columns
urls = urls.rename(columns={
    "URL": "url",
    "Label": "label"
})

# Remove missing values
urls = urls.dropna()

# Remove duplicate URLs
urls = urls.drop_duplicates(subset="url")

# Convert labels:
# good = 0 (legitimate)
# bad  = 1 (malicious/phishing)
urls["label"] = urls["label"].map({
    "good": 0,
    "bad": 1
})

# Remove rows where label conversion failed
urls = urls.dropna(subset=["label"])

# Convert label to integer
urls["label"] = urls["label"].astype(int)

print("URL dataset after cleaning:")
print(urls["label"].value_counts())


# ============================================
# BALANCE URL DATASET
# ============================================

# Find the size of the smaller class
n = min(
    25000,
    int(urls["label"].value_counts().min())
)

# Take equal samples from both classes
urls_balanced = (
    urls
    .groupby("label", group_keys=False)
    .sample(n=n, random_state=42)
)

# Shuffle the final dataset
urls_balanced = urls_balanced.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)

# Save processed URL dataset
urls_balanced.to_csv(
    "data/urls.csv",
    index=False
)

print("\nProcessed URL dataset:")
print("Rows:", len(urls_balanced))
print(urls_balanced["label"].value_counts())


# ============================================
# 2. PREPARE SMS DATASET
# ============================================

print("\nPreparing SMS dataset...")

# Load SMS dataset
messages = pd.read_csv(
    "data/raw_sms.csv",
    encoding="latin-1"
)

# Keep only the two useful columns.
# This automatically ignores:
# Unnamed: 2
# Unnamed: 3
# Unnamed: 4
messages = messages[["v1", "v2"]]

# Rename columns
messages.columns = ["label", "text"]

# Remove missing values
messages = messages.dropna()

# Remove duplicate messages
messages = messages.drop_duplicates(
    subset="text"
)

# Convert labels:
# ham  = 0 (normal message)
# spam = 1 (spam/scam message)
messages["label"] = messages["label"].map({
    "ham": 0,
    "spam": 1
})

# Remove rows where label conversion failed
messages = messages.dropna(subset=["label"])

# Convert label to integer
messages["label"] = messages["label"].astype(int)

# Save processed message dataset
messages.to_csv(
    "data/messages.csv",
    index=False
)

print("\nProcessed SMS dataset:")
print("Rows:", len(messages))
print(messages["label"].value_counts())


# ============================================
# COMPLETE
# ============================================

print("\n================================")
print("DATA PREPARATION COMPLETE")
print("================================")
print("Created:")
print("  data/urls.csv")
print("  data/messages.csv")