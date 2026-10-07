import streamlit as st
import pandas as pd

# Page configuration
st.set_page_config(
    page_title="AI Security Log Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# Title
st.title("🛡️ AI Security Log Analyzer")
st.write(
    "Analyze security logs and identify suspicious activity "
    "using automated threat detection."
)

st.divider()

# Upload section
st.header("📁 Upload Security Logs")

uploaded_file = st.file_uploader(
    "Upload a CSV file containing security logs",
    type=["csv"]
)

if uploaded_file is not None:

    try:
        data = pd.read_csv(uploaded_file)

        st.success("File uploaded successfully!")

        # Basic statistics
        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("Total Events", len(data))

        with col2:
            st.metric("Columns", len(data.columns))

        with col3:
            st.metric("File Size", f"{uploaded_file.size / 1024:.1f} KB")

        st.divider()

        # Preview
        st.subheader("📊 Log Preview")

        st.dataframe(
            data.head(20),
            use_container_width=True
        )

        st.divider()

        st.subheader("🔍 Dataset Information")

        st.write("Available columns:")

        for column in data.columns:
            st.write(f"- `{column}`")

    except Exception as error:

        st.error(
            f"Unable to analyze this file. Error: {error}"
        )

else:

    st.info(
        "Upload a CSV security log file to begin the analysis."
    )

st.divider()

st.caption(
    "AI Security Log Analyzer — Educational cybersecurity project"
      )
