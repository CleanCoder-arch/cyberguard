import os

from datetime import datetime



import pandas as pd

import streamlit as st



from cyberguard import analyze_input





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
    os.makedirs("data", exist_ok=True)

    history = load_history()

    preview = str(content).strip()

    if len(preview) > 120:
        preview = preview[:120] + "..."

    display_result = get_display_result(
        result,
        scan_type
    )

    new_record = pd.DataFrame(
        [{
            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "type": scan_type,
            "input": preview,
            "ml_prediction": display_result.get(
                "ml_prediction", "UNKNOWN"
            ),
            "risk_score": display_result.get(
                "risk_score", 0
            ),
            "risk_level": display_result.get(
                "risk_level", "LOW"
            )
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
# RESULT NORMALIZATION
# ============================================================

def get_display_result(result, input_type):
    """Normalize URL and SMS results for the Streamlit UI."""

    if not isinstance(result, dict):
        return {
            "risk_score": 0,
            "risk_level": "LOW",
            "recommendation": "No result available.",
            "ml_prediction": "UNKNOWN",
            "phishing_probability": 0.0,
            "malicious_probability": 0.0,
            "reasons": [],
            "positive_signals": [],
        }

    if input_type == "SMS":
        sms_result = result.get("sms_result", {})
        combined_risk = result.get("combined_risk", {})

        return {
            "risk_score": combined_risk.get("risk_score", 0),
            "risk_level": combined_risk.get("risk_level", "LOW"),
            "recommendation": combined_risk.get(
                "recommendation",
                "No strong risk indicators were detected."
            ),
            "ml_prediction": sms_result.get("ml_prediction", "UNKNOWN"),
            "phishing_probability": sms_result.get(
                "phishing_probability", 0.0
            ),
            "malicious_probability": 0.0,
            "reasons": sms_result.get("reasons", []),
            "positive_signals": sms_result.get("positive_signals", []),
        }

    return {
        "risk_score": result.get("risk_score", 0),
        "risk_level": result.get("risk_level", "LOW"),
        "recommendation": result.get(
            "recommendation",
            "No strong risk indicators were detected."
        ),
        "ml_prediction": result.get("ml_prediction", "UNKNOWN"),
        "phishing_probability": 0.0,
        "malicious_probability": result.get("malicious_probability", 0.0),
        "reasons": result.get("reasons", []),
        "positive_signals": result.get("positive_signals", []),
    }

# SESSION STATE

# ============================================================



if "last_result" not in st.session_state:



    st.session_state.last_result = None





if "last_input_type" not in st.session_state:



    st.session_state.last_input_type = None





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

        ]

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

        horizontal=True

    )





    # --------------------------------------------------------

    # URL

    # --------------------------------------------------------



    if scan_type == "URL":



        user_input = st.text_input(

            "Enter URL",

            placeholder="https://example.com"

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

            height=180

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



        if not user_input.strip():



            st.warning(

                "Please enter something to analyze."

            )



        else:



            with st.spinner(

                "Analyzing..."

            ):



                try:



                    result = analyze_input(

                        input_type,

                        user_input

                    )





                    st.session_state.last_result = result



                    st.session_state.last_input_type = input_type





                    save_scan(

                        input_type,

                        user_input,

                        result

                    )





                except Exception as e:



                    st.error(

                        "Analysis failed."

                    )



                    st.exception(e)





    # --------------------------------------------------------

    
# ============================================================
# DISPLAY RESULT
# ============================================================

result = st.session_state.last_result

if result is not None:

    result_input_type = st.session_state.get(
        "last_input_type"
    )

    display_result = get_display_result(
        result,
        result_input_type
    )

    st.divider()

    st.subheader(
        "📋 Analysis Result"
    )

    # --------------------------------------------------------
    # MAIN RISK CARD
    # --------------------------------------------------------

    risk_level = display_result["risk_level"]
    risk_score = display_result["risk_score"]

    if risk_level == "HIGH":

        st.markdown(
            f"""
            <div class="risk-high">
                <h2>🚨 HIGH RISK</h2>
                <p>
                    Risk Score:
                    <strong>{risk_score}/100</strong>
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

    elif risk_level == "MEDIUM":

        st.markdown(
            f"""
            <div class="risk-medium">
                <h2>⚠️ MEDIUM RISK</h2>
                <p>
                    Risk Score:
                    <strong>{risk_score}/100</strong>
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

    else:

        st.markdown(
            f"""
            <div class="risk-low">
                <h2>✅ LOW RISK</h2>
                <p>
                    Risk Score:
                    <strong>{risk_score}/100</strong>
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.write("")

    # --------------------------------------------------------
    # METRICS
    # --------------------------------------------------------

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Risk Score",
            f"{risk_score}/100"
        )

    with col2:
        st.metric(
            "Overall Risk",
            risk_level
        )

    with col3:

        if result_input_type == "URL":

            probability = (
                display_result["malicious_probability"] * 100
            )

            st.metric(
                "ML Malicious Probability",
                f"{probability:.2f}%"
            )

        else:

            probability = (
                display_result["phishing_probability"] * 100
            )

            st.metric(
                "ML Phishing Probability",
                f"{probability:.2f}%"
            )

    # --------------------------------------------------------
    # ML RESULT
    # --------------------------------------------------------

    st.subheader(
        "🧠 Machine Learning Signal"
    )

    st.write(
        f"**Prediction:** {display_result['ml_prediction']}"
    )

    st.caption(
        "The ML probability is one signal used by the overall "
        "risk engine. It is not itself the final risk assessment."
    )

    # --------------------------------------------------------
    # RISK INDICATORS
    # --------------------------------------------------------

    st.subheader(
        "⚠️ Risk Indicators"
    )

    if display_result.get("reasons"):

        for reason in display_result["reasons"]:
            st.warning(reason)

    else:

        st.success(
            "No major risk indicators detected."
        )

    # --------------------------------------------------------
    # POSITIVE SIGNALS
    # --------------------------------------------------------

    if display_result.get("positive_signals"):

        st.subheader(
            "✅ Positive Signals"
        )

        for signal in display_result["positive_signals"]:
            st.success(signal)

    # --------------------------------------------------------
    # SMS URL CROSS-ANALYSIS
    # --------------------------------------------------------

    if result_input_type == "SMS":

        detected_urls = result.get(
            "detected_urls",
            []
        )

        url_results = result.get(
            "url_results",
            []
        )

        st.subheader(
            "🔗 Detected Link Analysis"
        )

        if detected_urls:

            st.caption(
                f"{len(detected_urls)} unique URL(s) "
                "were detected inside this message."
            )

        else:

            st.info(
                "No URLs were detected inside this message."
            )

        for index, url_result in enumerate(
            url_results,
            start=1
        ):

            if not isinstance(url_result, dict):

                st.error(
                    "Invalid URL analysis result."
                )

                continue

            if "error" in url_result:

                st.error(
                    f"Unable to analyze "
                    f"{url_result.get('url', 'Unknown URL')}: "
                    f"{url_result['error']}"
                )

                continue

            url = url_result.get(
                "url",
                "Unknown URL"
            )

            url_risk = url_result.get(
                "risk_level",
                "UNKNOWN"
            )

            url_score = url_result.get(
                "risk_score",
                0
            )

            probability = (
                url_result.get(
                    "malicious_probability",
                    0
                ) * 100
            )

            with st.container(border=True):

                st.markdown(
                    f"### 🔗 URL {index}: `{url}`"
                )

                col1, col2, col3 = st.columns(3)

                with col1:

                    st.metric(
                        "URL Prediction",
                        url_result.get(
                            "ml_prediction",
                            "UNKNOWN"
                        )
                    )

                with col2:

                    st.metric(
                        "URL Risk",
                        f"{url_score}/100"
                    )

                with col3:

                    st.metric(
                        "Malicious Probability",
                        f"{probability:.2f}%"
                    )

                if url_risk == "HIGH":

                    st.error(
                        "🚨 URL Risk: HIGH"
                    )

                elif url_risk == "MEDIUM":

                    st.warning(
                        "⚠️ URL Risk: MEDIUM"
                    )

                else:

                    st.success(
                        "✅ URL Risk: LOW"
                    )

                reasons = url_result.get(
                    "reasons",
                    []
                )

                if reasons:

                    st.write(
                        "**URL Risk Indicators:**"
                    )

                    for reason in reasons:
                        st.warning(reason)

        # ----------------------------------------------------
        # COMBINED SMS + URL RISK
        # ----------------------------------------------------

        combined_risk = result.get(
            "combined_risk",
            {}
        )

        if combined_risk:

            st.subheader(
                "🛡️ Combined SMS + URL Risk"
            )

            col1, col2, col3 = st.columns(3)

            with col1:

                st.metric(
                    "Combined Score",
                    f"{combined_risk.get('risk_score', 0)}/100"
                )

            with col2:

                st.metric(
                    "Combined Risk",
                    combined_risk.get(
                        "risk_level",
                        "LOW"
                    )
                )

            with col3:

                st.metric(
                    "Suspicious URLs",
                    combined_risk.get(
                        "suspicious_url_count",
                        0
                    )
                )

            base_score = combined_risk.get(
                "base_score",
                0
            )

            multi_url_bonus = combined_risk.get(
                "multi_url_bonus",
                0
            )

            st.caption(
                f"Base risk: {base_score}/100 | "
                f"Multi-URL bonus: +{multi_url_bonus}"
            )

    # --------------------------------------------------------
    # URL DETAILS
    # --------------------------------------------------------

    if result_input_type == "URL":

        hostname = result.get(
            "hostname"
        )

        if hostname:

            st.subheader(
                "🌐 URL Details"
            )

            st.write(
                "**Hostname:**",
                hostname
            )

    # --------------------------------------------------------
    # RECOMMENDATION
    # --------------------------------------------------------

    st.subheader(
        "🛡️ Recommendation"
    )

    recommendation = display_result[
        "recommendation"
    ]

    if risk_level == "HIGH":

        st.error(recommendation)

    elif risk_level == "MEDIUM":

        st.warning(recommendation)

    else:

        st.info(recommendation)


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