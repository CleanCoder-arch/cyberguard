"""Render the scanner overview from the detector's existing results."""

from html import escape

from scan_summary import INCOMPLETE_ACTION


VERDICT_LABELS = {
    "LOW": ("low", "Low overall risk"),
    "MEDIUM": ("medium", "Medium overall risk"),
    "HIGH": ("high", "High overall risk"),
}


def _model_signal(input_type, detector_result):
    if detector_result is None:
        return "Unavailable"
    if input_type == "SMS":
        flagged_prediction = "PHISHING/SPAM"
        probability = detector_result["phishing_probability"]
    else:
        flagged_prediction = "MALICIOUS"
        probability = detector_result["malicious_probability"]
    label = "Flagged" if detector_result["ml_prediction"] == flagged_prediction else "Unflagged"
    return f"{label} · {probability:.2%}"


def _threat_feed_signal(result, input_type):
    feed = result.get("phishing_feed") or {}
    cache = {"fresh": "Fresh cache", "stale": "Stale cache"}.get(feed.get("status"))
    if cache is None:
        return "Cache unavailable"

    if input_type == "SMS":
        matches = [(link.get("phishing_feed") or {}).get("matched") for link in result["url_results"]]
        if True in matches:
            match = "Exact match found"
        elif result.get("url_extraction_error") or None in matches:
            match = "Link check incomplete"
        elif matches:
            match = "No exact match"
        else:
            match = "No links to check"
    else:
        match = {True: "Exact match found", False: "No exact match"}.get(
            feed.get("matched"), "Exact match could not be checked"
        )
    return f"{match} · {cache}"


def render_report_heading(is_sample=False):
    badge = '<span class="cg-sample-badge">Sample report</span>' if is_sample else ""
    return f'<div class="cg-report-heading"><h2>Scan result</h2>{badge}</div>'


def render_result_overview(result, input_type, verdict, detector_result):
    """Return the verdict, first-level signals, and action for the report card."""
    if verdict is None:
        tone, headline = "incomplete", "Analysis incomplete"
        score_markup = ""
        action = INCOMPLETE_ACTION
    else:
        tone, headline = VERDICT_LABELS[verdict["risk_level"]]
        score = escape(str(verdict["risk_score"]))
        score_markup = f'<p class="cg-verdict-score" aria-label="Risk score {score} out of 100">{score} / 100</p>'
        action = verdict["recommendation"]

    model_signal = escape(_model_signal(input_type, detector_result))
    feed_signal = escape(_threat_feed_signal(result, input_type))
    return f"""
        <div class="cg-result-overview">
            <div class="cg-verdict cg-verdict--{tone}" role="status">
                <span class="cg-verdict-icon" aria-hidden="true"></span>
                <div class="cg-verdict-content">
                    <h3>{headline}</h3>
                    {score_markup}
                </div>
            </div>
            <table class="cg-signals" aria-label="Scan signals">
                <tbody>
                    <tr><th scope="row">Model signal</th><td>{model_signal}</td></tr>
                    <tr><th scope="row">Threat feed</th><td>{feed_signal}</td></tr>
                </tbody>
            </table>
            <div class="cg-action">
                <span class="cg-action-icon" aria-hidden="true"></span>
                <div class="cg-action-content">
                    <h3>Recommended action</h3>
                    <p>{escape(action)}</p>
                </div>
            </div>
        </div>
    """
