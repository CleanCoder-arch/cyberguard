import pytest

from scan_summary import build_scan_summary


@pytest.mark.parametrize(
    ("source_type", "scan_type"), [("URL", "URL"), ("SMS", "SMS / Message"), ("QR", "QR code")]
)
def test_summary_contains_only_shareable_verdict_fields(source_type, scan_type):
    verdict = {
        "risk_level": "HIGH",
        "risk_score": 64,
        "url": "https://private.example/?reset=secret-token",
        "hostname": "private.example",
        "message": "Private message with a one-time code of 483762",
        "qr_payload": "raw QR payload",
        "recommendation": "Engine advice containing a private destination",
        "reasons": ["Private URL evidence"],
        "id": "private-history-id",
    }

    assert build_scan_summary(source_type, verdict).splitlines() == [
        "CyberGuard 2.0 scan summary",
        "",
        f"Scan type: {scan_type}",
        "Verdict: HIGH RISK",
        "Risk score: 64/100",
        "Recommended action: Avoid interacting with the content or sharing sensitive information.",
    ]


@pytest.mark.parametrize(
    "verdict",
    [
        None,
        {"risk_level": "private string", "risk_score": 64},
        {"risk_level": "HIGH", "risk_score": "private string"},
    ],
)
def test_summary_uses_a_fixed_fallback_for_an_incomplete_verdict(verdict):
    assert build_scan_summary("private source type", verdict).splitlines() == [
        "CyberGuard 2.0 scan summary",
        "",
        "Scan type: Unknown",
        "Verdict: Analysis incomplete",
        "Recommended action: Verify the source before interacting with the content.",
    ]
