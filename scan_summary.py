"""Build a shareable CyberGuard report from a small set of display fields."""

SCAN_TYPES = {"URL": "URL", "SMS": "SMS / Message", "QR": "QR code"}

RECOMMENDED_ACTIONS = {
    "HIGH": "Avoid interacting with the content or sharing sensitive information.",
    "MEDIUM": "Verify the source through an official channel before taking action.",
    "LOW": "Stay cautious and verify the source before sharing sensitive information.",
}
INCOMPLETE_ACTION = "Verify the source before interacting with the content."


def build_scan_summary(source_type, verdict):
    """Return a plain-text summary without scanned content or evidence."""
    scan_type = SCAN_TYPES.get(source_type, "Unknown")
    lines = ["CyberGuard 2.0 scan summary", "", f"Scan type: {scan_type}"]

    verdict = verdict or {}
    risk_level = verdict.get("risk_level")
    risk_score = verdict.get("risk_score")
    if (
        risk_level in RECOMMENDED_ACTIONS
        and type(risk_score) is int
        and 0 <= risk_score <= 100
    ):
        lines.extend((
            f"Verdict: {risk_level} RISK",
            f"Risk score: {risk_score}/100",
            f"Recommended action: {RECOMMENDED_ACTIONS[risk_level]}",
        ))
    else:
        lines.extend((
            "Verdict: Analysis incomplete",
            f"Recommended action: {INCOMPLETE_ACTION}",
        ))

    return "\n".join(lines) + "\n"
