import streamlit as st

from analyzer import analyze_url
from database import get_history, initialize_database, save_url_check
from config import DB_PATH

VT_API_KEY = st.secrets.get("VIRUSTOTAL_API_KEY", None)

initialize_database(DB_PATH)

st.set_page_config(
    page_title="Phishing Detector",
    page_icon="🛡️",
    layout="centered",
)

st.title("Phishing URL Detector")
st.write("Enter a URL and the app will analyze it for phishing signals.")

with st.form(key="analyze_form"):
    url_input = st.text_input("URL to analyze", placeholder="https://example.com/login")
    submit = st.form_submit_button("Analyze")

if submit:
    if not url_input.strip():
        st.error("Please enter a URL to analyze.")
    else:
        result = analyze_url(url_input, vt_api_key=VT_API_KEY)
        score = result["score"]
        level = result["level"]
        confidence = result["confidence"]

        if level == "Safe":
            st.success(f"Risk level: {level} ({score})")
        elif level == "Suspicious":
            st.warning(f"Risk level: {level} ({score})")
        else:
            st.error(f"Risk level: {level} ({score})")

        st.markdown(f"**Confidence:** {confidence}%")
        st.markdown(f"**Checked URL:** `{result['normalized_url']}`")

        st.subheader("Flags detected")
        for detail in result["details"]:
            status = "✅" if detail["score"] == 0 else "⚠️"
            st.write(f"{status} **{detail['name']}** — {detail['reason']}")


        if "virustotal" in result:
            vt = result["virustotal"]
            st.subheader("VirusTotal")
            if vt["success"]:
                st.write(f"🔴 Flagged by: {vt['positives']} engines")
                st.write(f"🔍 Total engines scanned: {vt['total']}")
                st.write(f"📋 {vt['message']}")
            else:
                st.write(f"VirusTotal lookup failed: {vt['message']}")

        save_url_check(
            DB_PATH,
            result["normalized_url"],
            score,
            level,
            confidence,
            notes=", ".join(
                detail["name"] for detail in result["details"] if detail["score"] > 0
            ),
        )

st.sidebar.header("History")
history = get_history(DB_PATH, limit=15)
if history:
    for row in history:
        st.sidebar.write(f"**{row['checked_at']}** — {row['level']} ({row['score']})")
        st.sidebar.write(f"{row['url']}  \nConfidence: {row['confidence']}%")
        if row["notes"]:
            st.sidebar.write(f"Flags: {row['notes']}")
        st.sidebar.markdown("---")
else:
    st.sidebar.write("No history yet.")
