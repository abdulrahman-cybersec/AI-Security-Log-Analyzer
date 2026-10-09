import streamlit as st
import pandas as pd
import io
import re

# =====================================
# Page Configuration
# =====================================

st.set_page_config(
    page_title="AI Security Log Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# =====================================
# Custom Interface
# =====================================

st.title("🛡️ Security Log Analyzer")

st.markdown(
    """
    Analyze security logs, identify suspicious patterns,
    and generate downloadable security reports.
    """
)

st.info(
    "This version uses transparent rule-based detection. "
    "It does not yet use a trained AI model."
)

st.divider()

# =====================================
# Detection Rules
# =====================================

def analyze_logs(data):

    results = data.copy()

    results.columns = [
        str(column).strip() for column in results.columns
    ]

    # Combine text fields for rule-based inspection.
    text_columns = results.select_dtypes(
        include=["object", "string"]
    ).columns

    combined_text = (
        results[text_columns]
        .fillna("")
        .astype(str)
        .agg(" ".join, axis=1)
        .str.lower()
    )

    # Initial, transparent detection rules.
    patterns = {
        "Possible brute-force activity":
            r"failed login|login failed|authentication failure|invalid password",

        "Possible malware activity":
            r"malware|ransomware|trojan|virus detected",

        "Possible unauthorized access":
            r"unauthorized|access denied|privilege escalation",

        "Possible scanning activity":
            r"port scan|network scan|nmap",

        "Possible injection attempt":
            r"sql injection|command injection|<script"
    }

    results["Detection"] = "No rule matched"
    results["Severity"] = "Informational"

    for description, pattern in patterns.items():

        matched = combined_text.str.contains(
            pattern,
            regex=True,
            na=False
        )

        new_match = (
            matched
            & results["Detection"].eq("No rule matched")
        )

        results.loc[new_match, "Detection"] = description
        results.loc[new_match, "Severity"] = "High"

    results["Suspicious"] = (
        results["Detection"] != "No rule matched"
    )

    return results


# =====================================
# File Upload
# =====================================

st.header("📁 Upload Security Logs")

uploaded_file = st.file_uploader(
    "Choose a CSV file",
    type=["csv"],
    help="Upload a security log file that you are authorized to analyze."
)

if uploaded_file is not None:

    try:

        data = pd.read_csv(
            uploaded_file,
            encoding="utf-8-sig",
            on_bad_lines="error"
        )

        if data.empty:
            st.warning("The uploaded file contains no data.")
            st.stop()

        if len(data.columns) > 100:
            st.error("The file contains too many columns.")
            st.stop()

        st.success("File uploaded successfully!")

        # =================================
        # Statistics
        # =================================

        total_events = len(data)
        total_columns = len(data.columns)
        missing_values = int(data.isna().sum().sum())

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Total Events", f"{total_events:,}")
        col2.metric("Total Columns", total_columns)
        col3.metric("Missing Values", f"{missing_values:,}")
        col4.metric(
            "File Size",
            f"{uploaded_file.size / 1024:.1f} KB"
        )

        st.divider()

        # =================================
        # Data Preview
        # =================================

        st.subheader("📊 Log Preview")

        st.dataframe(
            data.head(100),
            use_container_width=True
        )

        st.divider()

        # =================================
        # Detection
        # =================================

        st.subheader("🔎 Rule-Based Threat Detection")

        analyzed_data = analyze_logs(data)

        suspicious_data = analyzed_data[
            analyzed_data["Suspicious"]
        ]

        metric1, metric2, metric3 = st.columns(3)

        metric1.metric(
            "Suspicious Events",
            f"{len(suspicious_data):,}"
        )

        metric2.metric(
            "Events Without Matching Rules",
            f"{total_events - len(suspicious_data):,}"
        )

        metric3.metric(
            "Suspicious Rate",
            f"{len(suspicious_data) / total_events * 100:.1f}%"
        )

        st.caption(
            "A matching rule is an investigation lead, not proof "
            "that an event is malicious. Results depend on the "
            "text available in the uploaded logs."
        )

        st.subheader("🚨 Detection Results")

        if suspicious_data.empty:

            st.success(
                "No events matched the current detection rules."
            )

        else:

            st.warning(
                f"{len(suspicious_data)} event(s) matched "
                "one or more detection rules."
            )

            st.dataframe(
                suspicious_data,
                use_container_width=True
            )

        st.divider()

        # =================================
        # Download Report
        # =================================

        st.subheader("📥 Download Report")

        csv_buffer = io.StringIO()

        analyzed_data.to_csv(
            csv_buffer,
            index=False
        )

        st.download_button(
            label="Download Full Analysis (CSV)",
            data=csv_buffer.getvalue().encode("utf-8-sig"),
            file_name="security_analysis_report.csv",
            mime="text/csv"
        )

    except pd.errors.EmptyDataError:

        st.error("The uploaded file is empty or has no valid CSV columns.")

    except Exception:

        st.error(
            "Unable to process this file. "
            "Check that it is a valid CSV security log."
        )

else:

    st.info(
        "Upload a CSV file to explore the logs and run detection rules."
    )

    st.subheader("✨ Project Features")

    feature1, feature2, feature3 = st.columns(3)

    feature1.markdown(
        "**📊 Log Statistics**\n\n"
        "Review event counts, columns, and missing values."
    )

    feature2.markdown(
        "**🔍 Detection Rules**\n\n"
        "Search for selected suspicious patterns."
    )

    feature3.markdown(
        "**📥 Export Reports**\n\n"
        "Download the analysis for further investigation."
    )

st.divider()

st.caption(
    "Security Log Analyzer | Educational cybersecurity project"
    )
