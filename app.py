import os

from datetime import datetime



import pandas as pd

import streamlit as st



from cyberguard import analyze_input
from detector_models import DetectorUnavailableError
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





HISTORY_FILE = "data/scan_history.csv"





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



def load_history():



    if not os.path.exists(HISTORY_FILE):



        return pd.DataFrame(

            columns=[

                "timestamp",

                "type",

                "input",

                "ml_prediction",

                "risk_score",

                "risk_level"

            ]

        )



    try:



        return pd.read_csv(

            HISTORY_FILE

        )



    except Exception:



        return pd.DataFrame(

            columns=[

                "timestamp",

                "type",

                "input",

                "ml_prediction",

                "risk_score",

                "risk_level"

            ]

        )






def save_scan(
    scan_type,
    content,
    result
):
    verdict, detector_result = get_scan_results(result, scan_type)
    if verdict is None:
        return

    os.makedirs("data", exist_ok=True)

    history = load_history()

    preview = str(content).strip()

    if len(preview) > 120:
        preview = preview[:120] + "..."

    new_record = pd.DataFrame(
        [{
            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "type": scan_type,
            "input": preview,
            "ml_prediction": detector_result["ml_prediction"],
            "risk_score": verdict["risk_score"],
            "risk_level": verdict["risk_level"]
        }]
    )

    history = pd.concat(
        [history, new_record],
        ignore_index=True
    )

    history.to_csv(
        HISTORY_FILE,
        index=False
    )


# ============================================================
# SCAN REPORT
# ============================================================

def get_scan_results(result, input_type):
    """Return the overall verdict and the primary detector's result."""
    if input_type == "SMS":
        return result["combined_risk"], result["sms_result"]
    return result, result


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
        if "error" in link:
            st.error(f"Unable to analyze {link['url']}: {link['error']}")
            continue

        with st.container(border=True):
            st.markdown(f"### 🔗 URL {index}: `{link['url']}`")
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
        st.caption("The risk engine uses this probability alongside other indicators.")

        indicator_scope = "SMS " if input_type == "SMS" else ""
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
            st.caption(
                f"Base risk: {verdict['base_score']}/100 | "
                f"Multi-URL bonus: +{verdict['multi_url_bonus']}"
            )
    elif result.get("hostname"):
        st.subheader("🌐 URL Details")
        st.write("**Hostname:**", result["hostname"])
        if scheme := result.get("scheme"):
            st.write("**Scheme:**", scheme)

    if verdict is not None:
        st.subheader("🛡️ Recommendation")
        show_recommendation = {"HIGH": st.error, "MEDIUM": st.warning, "LOW": st.info}
        show_recommendation[risk_level](verdict["recommendation"])


def clear_scan_report():
    st.session_state.last_result = None


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



    st.markdown(

        '<div class="main-title">🛡️ CyberGuard</div>',

        unsafe_allow_html=True

    )



    st.markdown(

        '<div class="subtitle">'

        'AI-Powered URL & SMS Phishing Detection'

        '</div>',

        unsafe_allow_html=True

    )





    history = load_history()





    # --------------------------------------------------------

    # STATISTICS

    # --------------------------------------------------------



    total_scans = len(history)



    high_risk = 0

    medium_risk = 0

    low_risk = 0





    if total_scans > 0:



        high_risk = int(

            (

                history["risk_level"]

                == "HIGH"

            ).sum()

        )



        medium_risk = int(

            (

                history["risk_level"]

                == "MEDIUM"

            ).sum()

        )



        low_risk = int(

            (

                history["risk_level"]

                == "LOW"

            ).sum()

        )





    col1, col2, col3, col4 = st.columns(4)





    with col1:



        st.metric(

            "Total Scans",

            total_scans

        )





    with col2:



        st.metric(

            "🔴 High Risk",

            high_risk

        )





    with col3:



        st.metric(

            "🟠 Medium Risk",

            medium_risk

        )





    with col4:



        st.metric(

            "🟢 Low Risk",

            low_risk

        )





    st.divider()





    # --------------------------------------------------------

    # QUICK SCAN

    # --------------------------------------------------------



    st.subheader(

        "🔍 Quick Scan"

    )



    col1, col2 = st.columns(2)





    with col1:



        st.markdown(

            """

            ### 🔗 URL Scanner



            Detect suspicious and potentially

            malicious URLs using machine learning

            and URL security indicators.

            """

        )



        if st.button(

            "Open URL Scanner",

            use_container_width=True

        ):



            st.info(

                "Select 🔍 Scanner from the sidebar "

                "and choose URL."

            )





    with col2:



        st.markdown(

            """

            ### 📱 SMS Scanner



            Analyze suspicious messages for

            phishing, scam, account takeover,

            and social-engineering indicators.

            """

        )



        if st.button(

            "Open SMS Scanner",

            use_container_width=True

        ):



            st.info(

                "Select 🔍 Scanner from the sidebar "

                "and choose SMS / Message."

            )





    st.divider()





    # --------------------------------------------------------

    # SYSTEM OVERVIEW

    # --------------------------------------------------------



    st.subheader(

        "🧠 Detection System"

    )





    col1, col2, col3 = st.columns(3)





    with col1:



        st.markdown(

            """

            ### 🔗 URL ML



            Character-level TF-IDF combined

            with handcrafted URL features.



            **Domain-aware F1: 93.53%**

            """

        )





    with col2:



        st.markdown(

            """

            ### 📱 SMS ML



            Word-level TF-IDF with

            Logistic Regression.



            **Phishing F1: 93.70%**

            """

        )





    with col3:



        st.markdown(

            """

            ### 🛡️ Risk Engine



            Combines ML signals with

            explainable security indicators.



            **LOW / MEDIUM / HIGH**

            """

        )





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

        'Analyze a URL or suspicious message'

        '</div>',

        unsafe_allow_html=True

    )





    scan_type = st.radio(

        "Select scanner",

        [

            "URL",

            "SMS / Message"

        ],

        horizontal=True,
        on_change=clear_scan_report,
    )





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



    else:



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





    # --------------------------------------------------------

    # ANALYZE

    # --------------------------------------------------------



    if scan_button:
        clear_scan_report()
        if not user_input.strip():
            st.warning("Please enter something to analyze.")
        else:
            with st.spinner("Analyzing..."):
                try:
                    result = analyze_input(input_type, user_input)
                except (DetectorUnavailableError, URLValidationError) as exc:
                    st.error(str(exc))
                except Exception:
                    st.error("Analysis failed. Please try again.")
                else:
                    st.session_state.last_result = result
                    try:
                        save_scan(input_type, user_input, result)
                    except OSError:
                        st.warning("The scan report could not be saved to history.")

    if st.session_state.last_result is not None:
        render_scan_result(st.session_state.last_result, input_type)


# ============================================================
# ANALYTICS

# ============================================================



elif page == "📊 Analytics":



    st.markdown(

        '<div class="main-title">📊 Analytics</div>',

        unsafe_allow_html=True

    )



    st.markdown(

        '<div class="subtitle">'

        'CyberGuard model performance'

        '</div>',

        unsafe_allow_html=True

    )





    st.subheader(

        "🔗 URL Detector"

    )





    url_metrics = pd.DataFrame(

        {

            "Metric": [

                "Accuracy",

                "Precision",

                "Recall",

                "F1 Score"

            ],



            "Score": [

                0.9368,

                0.9403,

                0.9303,

                0.9353

            ]

        }

    )





    url_display = url_metrics.copy()



    url_display["Score"] = (

        url_display["Score"] * 100

    ).round(2).astype(str) + "%"





    st.dataframe(

        url_display,

        hide_index=True,

        use_container_width=True

    )





    st.bar_chart(

        url_metrics.set_index("Metric")

    )





    st.caption(

        "URL figures shown here come from the "

        "domain-aware evaluation with zero "

        "hostname overlap between training and testing."

    )





    st.divider()





    st.subheader(

        "📱 SMS Detector"

    )





    sms_metrics = pd.DataFrame(

        {

            "Metric": [

                "Accuracy",

                "Precision",

                "Recall",

                "F1 Score"

            ],



            "Score": [

                0.9845,

                0.9675,

                0.9084,

                0.9370

            ]

        }

    )





    sms_display = sms_metrics.copy()



    sms_display["Score"] = (

        sms_display["Score"] * 100

    ).round(2).astype(str) + "%"





    st.dataframe(

        sms_display,

        hide_index=True,

        use_container_width=True

    )





    st.bar_chart(

        sms_metrics.set_index("Metric")

    )





    st.caption(

        "SMS metrics are based on the stratified "

        "test set used during model evaluation."

    )





    st.divider()





    st.subheader(

        "🛡️ Risk Classification"

    )





    risk_data = pd.DataFrame(

        {

            "Risk Level": [

                "LOW",

                "MEDIUM",

                "HIGH"

            ],



            "Score Range": [

                "0–29",

                "30–59",

                "60–100"

            ]

        }

    )





    st.dataframe(

        risk_data,

        hide_index=True,

        use_container_width=True

    )





# ============================================================

# SCAN HISTORY

# ============================================================



elif page == "📜 Scan History":



    st.markdown(

        '<div class="main-title">📜 Scan History</div>',

        unsafe_allow_html=True

    )



    st.markdown(

        '<div class="subtitle">'

        'Previous CyberGuard analyses'

        '</div>',

        unsafe_allow_html=True

    )





    history = load_history()





    if history.empty:



        st.info(

            "No scans have been recorded yet."

        )



    else:



        st.subheader(

            f"Total recorded scans: {len(history)}"

        )





        display_history = history.iloc[

            ::-1

        ].reset_index(

            drop=True

        )





        st.dataframe(

            display_history,

            hide_index=True,

            use_container_width=True

        )





        st.divider()





        if st.button(

            "🗑️ Clear Scan History"

        ):



            if os.path.exists(

                HISTORY_FILE

            ):



                os.remove(

                    HISTORY_FILE

                )





            st.success(

                "Scan history cleared."

            )



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