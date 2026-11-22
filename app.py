import sqlite3
from pathlib import Path
from time import perf_counter



import pandas as pd

import streamlit as st



from benchmark_results import load_stage3b_benchmark
from cyberguard import analyze_input
from detector_models import DetectorUnavailableError
from qr_scanner import MAX_IMAGE_BYTES, QRScanError, decode_qr_image
from scan_history import FEED_STATES, HISTORY_COLUMNS, INPUT_TYPES, RISK_LEVELS, ScanHistory
from url_normalizer import URLValidationError





# ============================================================

# CONFIGURATION

# ============================================================



st.set_page_config(

    page_title="CyberGuard",

    page_icon="🛡️",

    layout="wide",

    initial_sidebar_state="expanded"

)





HISTORY_DATABASE = Path("data/scan_history.sqlite3")
LEGACY_HISTORY_FILE = Path("data/scan_history.csv")





# ============================================================

# CUSTOM CSS

# ============================================================



st.markdown(

    """

    <style>



    .main-title {

        font-size: 42px;

        font-weight: 800;

        margin-bottom: 0;

    }



    .subtitle {

        font-size: 18px;

        margin-bottom: 25px;

        opacity: 0.75;

    }



    .dashboard-card {

        padding: 22px;

        border-radius: 14px;

        border: 1px solid rgba(128,128,128,0.25);

        margin-bottom: 15px;

    }



    .big-number {

        font-size: 34px;

        font-weight: 700;

    }



    .small-label {

        font-size: 14px;

        opacity: 0.7;

    }



    .risk-high {

        padding: 18px;

        border-radius: 12px;

        background: rgba(255, 75, 75, 0.15);

        border: 1px solid rgba(255, 75, 75, 0.35);

    }



    .risk-medium {

        padding: 18px;

        border-radius: 12px;

        background: rgba(255, 180, 0, 0.15);

        border: 1px solid rgba(255, 180, 0, 0.35);

    }



    .risk-low {

        padding: 18px;

        border-radius: 12px;

        background: rgba(50, 200, 100, 0.15);

        border: 1px solid rgba(50, 200, 100, 0.35);

    }



    </style>

    """,

    unsafe_allow_html=True

)





# ============================================================

# HISTORY FUNCTIONS

# ============================================================



def get_history_store():
    store = ScanHistory(HISTORY_DATABASE)
    try:
        store.import_legacy_csv(LEGACY_HISTORY_FILE)
    except (OSError, ValueError, sqlite3.Error):
        st.warning("Legacy scan metadata could not be imported.")
    return store


def load_history(**filters):
    try:
        rows = get_history_store().read(**filters)
    except (OSError, sqlite3.Error):
        st.error("Scan history is temporarily unavailable.")
        rows = []
    return pd.DataFrame.from_records(rows, columns=HISTORY_COLUMNS)


def save_scan(source_type, result, latency_ms):
    status = "failed"
    risk_level = None
    feed_freshness = None
    if result is not None:
        scan_type = "SMS" if "sms_result" in result else "URL"
        verdict, _ = get_scan_results(result, scan_type)
        status = "completed" if verdict is not None else "incomplete"
        risk_level = verdict["risk_level"] if verdict is not None else None
        feed_freshness = result.get("phishing_feed", {}).get("status")
    get_history_store().record(
        source_type, status, risk_level=risk_level,
        latency_ms=latency_ms, feed_freshness=feed_freshness,
    )


def filter_history():
    with st.container(border=True):
        from_col, to_col, type_col = st.columns(3)
        start_date = from_col.date_input("From date (UTC)", value=None, format="YYYY-MM-DD")
        end_date = to_col.date_input("To date (UTC)", value=None, format="YYYY-MM-DD")
        input_type = type_col.selectbox("Input type", ("All types", *INPUT_TYPES))
    if start_date is not None and end_date is not None and start_date > end_date:
        st.warning("Choose an end date on or after the start date.")
        return pd.DataFrame(columns=HISTORY_COLUMNS)
    return load_history(
        start_date=start_date,
        end_date=end_date,
        input_type=None if input_type == "All types" else input_type,
    )


def render_history_totals(history):
    counts = history["scan_status"].value_counts()
    for column, (label, value) in zip(st.columns(4), (
        ("Total scans", len(history)),
        ("Completed", counts.get("completed", 0)),
        ("Incomplete", counts.get("incomplete", 0)),
        ("Failed", counts.get("failed", 0)),
    )):
        column.metric(label, int(value), border=True)


def render_scan_volume(history):
    days = pd.to_datetime(history["timestamp"], utc=True).dt.strftime("%Y-%m-%d")
    daily = pd.crosstab(days, history["input_type"]).reindex(columns=INPUT_TYPES, fill_value=0)
    st.bar_chart(
        daily, x_label="Scan date (UTC)", y_label="Scans", height=220, stack=True,
        color=["#3f76d3", "#188976", "#a05dbb"],
    )


def render_history_table(history):
    display = history.copy()
    display["timestamp"] = pd.to_datetime(display["timestamp"], utc=True).dt.strftime("%Y-%m-%d %H:%M:%S")
    display["scan_status"] = display["scan_status"].str.capitalize()
    display["feed_freshness"] = display["feed_freshness"].fillna("unrecorded").str.capitalize()
    st.dataframe(display, hide_index=True, column_config={
        "timestamp": "Timestamp (UTC)",
        "input_type": "Input type",
        "scan_status": "Status",
        "risk_level": "Risk level",
        "latency_ms": st.column_config.NumberColumn("Latency (ms)", format="%.1f"),
        "feed_freshness": "Feed freshness",
    })


def render_stage3b_benchmark():
    st.subheader("Locked Stage 3B benchmark")
    benchmark = load_stage3b_benchmark()
    if benchmark is None:
        st.info("Locked Stage 3B benchmark results are missing or invalid. Run evaluate_stage3b.py to generate them.")
        return

    st.caption(
        f"Held-out test results from {benchmark['run']} (seed {benchmark['seed']}). "
        "Candidate selection and thresholds were locked on validation."
    )
    for column, task_key in zip(st.columns(2), ("url", "sms")):
        task = benchmark["tasks"][task_key]
        with column:
            st.markdown(f"#### {task['label']}")
            selected = next(model for model in task["models"] if model["selected"])
            st.caption(f"Selected on validation · {selected['model']} · {selected['features']}")
            st.dataframe(pd.DataFrame([
                {
                    "Benchmarked model": model["model"],
                    "Accuracy": f"{model['accuracy']:.2%}",
                    "Recall": f"{model['recall']:.2%}",
                    "F1": f"{model['f1']:.2%}",
                    "False-positive rate": f"{model['false_positive_rate']:.2%}",
                }
                for model in task["models"]
            ]), hide_index=True)
            if task_key == "sms":
                st.caption(
                    "The calibrated linear SVM was benchmarked offline for spam detection. "
                    "The deployed SMS scanner uses a separate TF-IDF logistic regression and risk rules."
                )


# ============================================================
# SCAN REPORT
# ============================================================

def get_scan_results(result, input_type):
    """Return the overall verdict and the primary detector's result."""
    if input_type == "SMS":
        return result["combined_risk"], result["sms_result"]
    return result, result


def render_scan_checks(checks):
    if not checks:
        return

    incomplete = any(
        check["status"] == "failed" or (check["check"] == "Overall risk" and check["status"] == "skipped")
        for check in checks
    )
    with st.expander("Scan checks", expanded=incomplete):
        for check in checks:
            parts = [check["status"].capitalize(), check["check"]]
            if url := check.get("url"):
                parts.append(url)
            if detail := check.get("detail"):
                parts.append(detail)
            st.text(" · ".join(parts))


def render_model_explanation(result):
    explanation = result.get("model_explanation")
    if not explanation:
        return
    if explanation.get("status") == "unavailable":
        st.caption("Feature contributions are unavailable for this model.")
        return

    positive_class = explanation["positive_class"]
    if result["ml_prediction"] == positive_class and result["risk_level"] == "LOW":
        st.caption(
            "The model flagged this input. Its probability contributes through a scoring "
            f"rule, and the rules total {result['risk_score']}/100. MEDIUM risk starts at 30."
        )

    feature_types = {
        "url_tfidf": "URL text",
        "url_structure": "URL structure",
        "sms_tfidf": "SMS text",
    }
    contributions = explanation["positive"] + explanation["negative"]
    with st.expander("Strongest model feature contributions"):
        st.caption(
            f"Positive contributions increase the model's probability of {positive_class}. "
            "Negative contributions decrease it. Values are in log-odds."
        )
        if contributions:
            rows = []
            for item in contributions:
                row = {
                    "Feature": item["feature"],
                    "Type": feature_types[item["kind"]],
                    "Contribution": f"{item['contribution']:+.3f}",
                }
                if "value" in item:
                    row["Input value"] = f"{item['value']:g}"
                rows.append(row)
            st.dataframe(pd.DataFrame(rows), hide_index=True)
            if any("value" in item for item in contributions):
                st.caption(
                    "The table shows original URL structure values. "
                    "The model scales those values before weighting them."
                )
        else:
            st.caption("The model found no nonzero feature contributions for this input.")
        st.caption(
            f"Baseline {explanation['baseline']:+.3f} · "
            f"Other features {explanation['other_contribution']:+.3f} · "
            f"Total {explanation['total']:+.3f}"
        )


def render_score_breakdown(breakdown, label="Risk score changes"):
    if not breakdown:
        return

    with st.expander(label):
        st.text(f"Starting score {breakdown['starting_score']}/100")
        for adjustment in breakdown["adjustments"]:
            st.text(f"{adjustment['delta']:+} points · {adjustment['rule']}")
        if not breakdown["adjustments"]:
            st.caption("No scoring rules changed the starting score.")
        st.text(f"Final score {breakdown['final_score']}/100")


def render_phishing_feed(feed):
    if not feed:
        return

    label = f"{feed['provider']} phishing feed"
    status = feed["status"]
    matched = feed.get("matched")
    if status == "unavailable":
        st.info(f"{label} · Cache unavailable")
    elif matched is True:
        st.warning(f"{label} · Exact match found")
        st.caption("The provider lists this URL as suspicious. Verify it independently.")
    elif matched is False:
        st.caption(f"{label} · No exact match")
    elif "matched" in feed:
        st.info(f"{label} · Exact match could not be checked for this URL")
    else:
        st.caption(label)

    if refreshed_at := feed.get("refreshed_at"):
        st.caption(f"{status.capitalize()} cache · Last successful refresh {refreshed_at}")
    else:
        st.caption("No successful refresh yet")


def render_link_analysis(result):
    st.subheader("🔗 Detected Link Analysis")

    if result.get("url_extraction_error"):
        st.error(result["url_extraction_error"])
    elif result["detected_urls"]:
        st.caption(
            f"{len(result['detected_urls'])} unique URL(s) "
            "were detected inside this message."
        )
    else:
        st.info("No URLs were detected inside this message.")

    for index, link in enumerate(result["url_results"], start=1):
        with st.container(border=True):
            st.markdown(f"### 🔗 URL {index}")
            st.text(link["url"])
            render_phishing_feed(link.get("phishing_feed"))
            if "error" in link:
                st.error("Unable to analyze this URL")
                st.text(link["error"])
                continue

            if scheme := link.get("scheme"):
                st.caption(f"Scheme: {scheme}")
            prediction_col, score_col, probability_col = st.columns(3)
            prediction_col.metric("URL Prediction", link["ml_prediction"])
            score_col.metric("URL Risk", f"{link['risk_score']}/100")
            probability_col.metric(
                "Malicious Probability", f"{link['malicious_probability'] * 100:.2f}%"
            )

            risk_message = {
                "HIGH": (st.error, "🚨 URL Risk: HIGH"),
                "MEDIUM": (st.warning, "⚠️ URL Risk: MEDIUM"),
                "LOW": (st.success, "✅ URL Risk: LOW"),
            }
            show_message, message = risk_message[link["risk_level"]]
            show_message(message)

            if link["reasons"]:
                st.write("**URL Risk Indicators:**")
                for reason in link["reasons"]:
                    st.warning(reason)

            render_model_explanation(link)
            render_score_breakdown(link.get("score_breakdown"), "URL risk score changes")


def render_scan_result(result, input_type):
    verdict, detector_result = get_scan_results(result, input_type)
    st.divider()
    st.subheader("📋 Analysis Result")

    if verdict is None:
        st.warning("Analysis incomplete. An overall verdict is unavailable.")
    else:
        risk_level = verdict["risk_level"]
        risk_score = verdict["risk_score"]
        icon = {"HIGH": "🚨", "MEDIUM": "⚠️", "LOW": "✅"}[risk_level]
        st.markdown(
            f"""
            <div class="risk-{risk_level.lower()}">
                <h2>{icon} {risk_level} RISK</h2>
                <p>Risk Score: <strong>{risk_score}/100</strong></p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    if input_type != "SMS" or not result["url_results"]:
        render_phishing_feed(result.get("phishing_feed"))
    render_scan_checks(result.get("checks"))

    if detector_result is None:
        st.error(result["sms_error"])
    else:
        if input_type == "SMS":
            probability = detector_result["phishing_probability"]
            probability_label = "ML Phishing Probability"
        else:
            probability = detector_result["malicious_probability"]
            probability_label = "ML Malicious Probability"

        if verdict is None:
            score_col, risk_col, probability_col = st.columns(3)
            score_col.metric("SMS Risk Score", f"{detector_result['risk_score']}/100")
            risk_col.metric("SMS Risk Level", detector_result["risk_level"])
        else:
            score_col, risk_col, probability_col = st.columns(3)
            score_col.metric("Risk Score", f"{risk_score}/100")
            risk_col.metric("Overall Risk", risk_level)

        probability_col.metric(probability_label, f"{probability * 100:.2f}%")
        st.subheader("🧠 Machine Learning Signal")
        st.write(f"**Prediction:** {detector_result['ml_prediction']}")
        render_model_explanation(detector_result)

        indicator_scope = "SMS " if input_type == "SMS" else ""
        score_label = "SMS risk score changes" if input_type == "SMS" else "Risk score changes"
        render_score_breakdown(detector_result.get("score_breakdown"), score_label)
        st.subheader(f"⚠️ {indicator_scope}Risk Indicators")
        if detector_result["reasons"]:
            for reason in detector_result["reasons"]:
                st.warning(reason)
        else:
            st.success(f"No major {indicator_scope}risk indicators detected.")

        if detector_result["positive_signals"]:
            st.subheader(f"✅ {indicator_scope}Positive Signals")
            for signal in detector_result["positive_signals"]:
                st.success(signal)

    if input_type == "SMS":
        render_link_analysis(result)
        if verdict is not None:
            st.subheader("🛡️ Combined SMS + URL Risk")
            score_col, risk_col, links_col = st.columns(3)
            score_col.metric("Combined Score", f"{risk_score}/100")
            risk_col.metric("Combined Risk", risk_level)
            links_col.metric("Suspicious URLs", verdict["suspicious_url_count"])
            if breakdown := verdict.get("score_breakdown"):
                st.caption("The combined score starts with the highest SMS or linked URL score.")
                render_score_breakdown(breakdown, "Combined risk score changes")
            else:
                st.caption(
                    f"Base risk: {verdict['base_score']}/100 | "
                    f"Multi-URL bonus: +{verdict['multi_url_bonus']}"
                )
    elif result.get("hostname"):
        st.subheader("🌐 URL Details")
        st.text(f"Hostname: {result['hostname']}")
        if scheme := result.get("scheme"):
            st.write("**Scheme:**", scheme)

    if verdict is not None:
        st.subheader("🛡️ Recommendation")
        show_recommendation = {"HIGH": st.error, "MEDIUM": st.warning, "LOW": st.info}
        show_recommendation[risk_level](verdict["recommendation"])


def clear_scan_report():
    st.session_state.last_result = None


def open_scanner(mode):
    st.session_state.active_page = "🔍 Scanner"
    st.session_state.scanner_mode = mode
    clear_scan_report()


st.session_state.setdefault("last_result", None)


# ============================================================

# SIDEBAR

# ============================================================



with st.sidebar:



    st.markdown(

        "# 🛡️ CyberGuard"

    )



    st.caption(

        "AI-Powered Cyber Threat Detection"

    )



    st.divider()





    page = st.radio(

        "Navigation",

        [

            "🏠 Dashboard",

            "🔍 Scanner",

            "📊 Analytics",

            "📜 Scan History",

            "ℹ️ About"

        ],
        key="active_page",
        on_change=clear_scan_report,
    )





    st.divider()





    st.markdown(

        "### Detection Modules"

    )



    st.markdown(

        """

        🔗 URL Detection



        📱 SMS Detection



        🧠 Machine Learning



        🛡️ Risk Analysis

        """

    )





# ============================================================

# DASHBOARD

# ============================================================



if page == "🏠 Dashboard":
    st.title("CyberGuard Dashboard")
    st.caption("Scan a URL, SMS message, or QR image and review local scan activity.")

    with st.container(border=True):
        st.subheader("Start a scan")
        for column, (label, mode) in zip(st.columns(3), (
            ("Scan a URL", "URL"),
            ("Scan an SMS", "SMS / Message"),
            ("Scan a QR image", "QR Image"),
        )):
            column.button(label, width="stretch", on_click=open_scanner, args=(mode,))

    st.subheader("Scan activity")
    history = filter_history()
    render_history_totals(history)
    if history.empty:
        st.info("No scans match these filters. Start a scan to add an entry.")
    else:
        st.subheader("Scans by day and input type")
        render_scan_volume(history)
        st.subheader("Recent scans")
        render_history_table(history.head(7))


# ============================================================

# SCANNER

# ============================================================



elif page == "🔍 Scanner":



    st.markdown(

        '<div class="main-title">🔍 Security Scanner</div>',

        unsafe_allow_html=True

    )



    st.markdown(

        '<div class="subtitle">'

        'Analyze a URL, message, or QR image'

        '</div>',

        unsafe_allow_html=True

    )





    scan_type = st.radio(

        "Select scanner",

        [

            "URL",

            "SMS / Message",

            "QR Image"

        ],

        horizontal=True,
        key="scanner_mode",
        on_change=clear_scan_report,
    )

    qr_scan = scan_type == "QR Image"





    # --------------------------------------------------------

    # URL

    # --------------------------------------------------------



    if scan_type == "URL":



        user_input = st.text_input(

            "Enter URL",

            placeholder="https://example.com",
            on_change=clear_scan_report,
        )





        scan_button = st.button(

            "🔍 Analyze URL",

            type="primary"

        )





        input_type = "URL"





    # --------------------------------------------------------

    # SMS

    # --------------------------------------------------------



    elif scan_type == "SMS / Message":



        user_input = st.text_area(

            "Enter message",

            placeholder=(

                "Paste the suspicious SMS or "

                "message here..."

            ),

            height=180,
            on_change=clear_scan_report,
        )





        scan_button = st.button(

            "🔍 Analyze Message",

            type="primary"

        )





        input_type = "SMS"


    else:
        uploaded_image = st.file_uploader(
            "Upload a QR image",
            type=["png", "jpg", "jpeg"],
            max_upload_size=MAX_IMAGE_BYTES // (1024 * 1024),
            on_change=clear_scan_report,
        )
        scan_button = st.button("🔍 Analyze QR Image", type="primary")




    # --------------------------------------------------------

    # ANALYZE

    # --------------------------------------------------------



    if scan_button:
        clear_scan_report()
        if qr_scan and uploaded_image is None:
            st.warning("Upload a PNG or JPEG image to analyze.")
        elif not qr_scan and not user_input.strip():
            st.warning("Please enter something to analyze.")
        else:
            with st.spinner("Analyzing..."):
                started = perf_counter()
                source_type = "QR" if qr_scan else input_type
                result = None
                try:
                    if qr_scan:
                        input_type, user_input = decode_qr_image(uploaded_image.getvalue())
                    result = analyze_input(input_type, user_input)
                except (DetectorUnavailableError, URLValidationError, QRScanError) as exc:
                    st.error(str(exc))
                except Exception:
                    st.error("Analysis failed. Please try again.")
                else:
                    st.session_state.last_result = result
                try:
                    save_scan(source_type, result, (perf_counter() - started) * 1000)
                except (OSError, sqlite3.Error):
                    st.warning("Scan metadata could not be saved to history.")

    if (result := st.session_state.last_result) is not None:
        report_type = "SMS" if "sms_result" in result else "URL"
        if qr_scan:
            payload_type = "a web URL" if report_type == "URL" else "a text message"
            st.caption(f"QR image decoded locally as {payload_type}.")
            if report_type == "URL":
                st.text(f"Decoded URL: {result['url']}")
        render_scan_result(result, report_type)


# ============================================================
# ANALYTICS

# ============================================================



elif page == "📊 Analytics":
    st.title("Analytics")
    st.caption("Scan activity, detector outcomes, and held-out benchmark results.")
    history = filter_history()
    render_history_totals(history)

    if history.empty:
        st.info("No scans match these filters. Scan activity will appear here when records are available.")
    else:
        st.subheader("Scans by day and input type")
        render_scan_volume(history)
        verdict_column, feed_column = st.columns(2, gap="medium")
        with verdict_column:
            st.subheader("Verdicts by input type")
            verdicts = pd.crosstab(history["input_type"], history["risk_level"]).reindex(
                index=INPUT_TYPES, columns=RISK_LEVELS, fill_value=0,
            )
            st.dataframe(verdicts.reset_index(names="Input type"), hide_index=True)
        with feed_column:
            st.subheader("Feed freshness")
            freshness = history["feed_freshness"].fillna("unrecorded").value_counts().reindex(
                (*FEED_STATES, "unrecorded"), fill_value=0,
            )
            st.dataframe(pd.DataFrame({
                "Cache state": freshness.index.str.capitalize(), "Scans": freshness.to_numpy(),
            }), hide_index=True)

        st.subheader("Scan latency")
        latencies = history["latency_ms"].dropna()
        if latencies.empty:
            st.caption("No latency measurements are available for these scans.")
        else:
            median_col, p95_col, measured_col = st.columns(3)
            median_col.metric("Median latency", f"{latencies.median():.1f} ms", border=True)
            p95_col.metric("95th percentile latency", f"{latencies.quantile(0.95):.1f} ms", border=True)
            measured_col.metric("Measured scans", len(latencies), border=True)

    st.divider()
    render_stage3b_benchmark()


# ============================================================

# SCAN HISTORY

# ============================================================



elif page == "📜 Scan History":
    st.title("Scan History")
    st.caption("Saved scan metadata. Timestamps and date filters use UTC.")
    history = filter_history()
    if history.empty:
        st.info("No scans match these filters.")
    else:
        st.caption(f"{len(history):,} matching scans")
        render_history_table(history)
        if st.button("Clear all saved scans"):
            try:
                get_history_store().clear()
            except (OSError, sqlite3.Error):
                st.error("Scan history could not be cleared.")
            else:
                st.rerun()


# ============================================================

# ABOUT

# ============================================================



elif page == "ℹ️ About":



    st.markdown(

        '<div class="main-title">ℹ️ About CyberGuard</div>',

        unsafe_allow_html=True

    )





    st.markdown(

        """

        ## 🛡️ CyberGuard



        CyberGuard is an AI-powered cybersecurity

        project designed to analyze potentially

        malicious URLs and phishing messages.



        ### Detection Modules



        **🔗 URL Detection**



        Uses character-level TF-IDF combined with

        handcrafted URL security features and a

        hybrid machine-learning model.



        **📱 SMS Detection**



        Uses TF-IDF text representation and

        Logistic Regression to identify

        phishing/spam messages.



        **🧠 Explainable Risk Engine**



        Machine-learning signals are combined with

        security indicators to produce a risk score

        and explainable reasons.



        ### Risk Levels



        | Score | Level |

        |---:|---|

        | 0–29 | LOW |

        | 30–59 | MEDIUM |

        | 60–100 | HIGH |



        ### Important Note



        CyberGuard provides an automated assessment

        and should not be treated as a guarantee that

        a URL or message is safe or malicious.

        Users should independently verify important

        security decisions.



        ### Technology Stack



        - Python

        - Scikit-learn

        - Pandas

        - Streamlit

        - TF-IDF

        - Logistic Regression

        - Hybrid URL feature engineering

        """

    )





# ============================================================

# FOOTER

# ============================================================



st.divider()



st.caption(

    "CyberGuard — AI-powered cybersecurity threat detection system"

)
