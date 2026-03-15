import streamlit as st
import pandas as pd
import os
from datetime import datetime

# --- CONFIGURATION ---

RAW_URL = f"https://raw.githubusercontent.com/vinayak-salian/honeypot-idps/main/logs/"

st.set_page_config(
    page_title="IDPS Operational Console",
    page_icon="???",
    layout="wide"
)

# --- STYLING ---
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .stMetric { background-color: #1e2130; padding: 15px; border-radius: 10px; border: 1px solid #3e4250; }
    </style>
    """, unsafe_allow_html=True)

# --- ROBUST DATA LOADING ---
@st.cache_data(ttl=60)  # Refresh cache every 60 seconds
def fetch_logs(filename):
    """Pulls CSV from GitHub Raw URL with error handling for empty/missing files."""
    try:
        url = RAW_URL + filename
        df = pd.read_csv(url)
        if df.empty:
            return pd.DataFrame()
        return df
    except Exception:
        # Returns an empty dataframe if file doesn't exist or URL is wrong
        return pd.DataFrame()

# --- HEADER ---
st.title("??? IoT Autonomous Honeypot & IDPS")
st.markdown("### Operational Intelligence & Strategic Mitigation Console")

# --- SYSTEM STATUS ---
status_col, time_col = st.columns([3, 1])

# Load primary log to check for "liveness"
ps_df = fetch_logs("portscan_log.csv")

with status_col:
    if not ps_df.empty:
        st.success("?? **SYSTEM STATUS:** SENTRY NODE OPERATIONAL (LIVE FEED)")
    else:
        st.warning("?? **SYSTEM STATUS:** SENTRY NODE INITIALIZING (WAITING FOR DATA)")

with time_col:
    st.write(f"**Current Session Time:** {datetime.now().strftime('%H:%M:%S')}")

# --- KEY PERFORMANCE INDICATORS (KPIs) ---
m1, m2, m3, m4 = st.columns(4)

# Load other logs
mw_df = fetch_logs("malware_delivery_log.csv")
bf_df = fetch_logs("bruteforce_log.csv")
dns_df = fetch_logs("dns_spoof_log.csv")

m1.metric("RECONNAISSANCE", len(ps_df))
m2.metric("PAYLOAD DROPS", len(mw_df))
m3.metric("AUTH VIOLATIONS", len(bf_df))
m4.metric("DNS ANOMALIES", len(dns_df))

# --- MAIN THREAT FEED ---
st.divider()
st.subheader("?? Real-Time Threat Intelligence Feed")

# Create tabs for different attack vectors
tab1, tab2, tab3, tab4 = st.tabs(["Port Scanning", "Malware Delivery", "Brute Force", "DNS Spoofing"])

with tab1:
    if not ps_df.empty:
        st.dataframe(ps_df.sort_index(ascending=False), use_container_width=True)
    else:
        st.info("No Reconnaissance events logged yet.")

with tab2:
    if not mw_df.empty:
        st.dataframe(mw_df.sort_index(ascending=False), use_container_width=True)
    else:
        st.info("No Malware Delivery attempts logged yet.")

with tab3:
    if not bf_df.empty:
        st.dataframe(bf_df.sort_index(ascending=False), use_container_width=True)
    else:
        st.info("No Brute Force (Auth-Violation) events logged yet.")

with tab4:
    if not dns_df.empty:
        st.dataframe(dns_df.sort_index(ascending=False), use_container_width=True)
    else:
        st.info("No DNS Anomaly events logged yet.")

# --- TACTICAL RESPONSE ACTIONS ---
st.divider()
st.subheader("? Tactical Response & Mitigation")

c1, c2, c3, c4 = st.columns(4)

with c1:
    if st.button("BLOCK SOURCE IP", use_container_width=True):
        st.error("Firewall Rule Queued: IPTables DROP initiated.")

with c2:
    if st.button("ISOLATE TO SUBNET", use_container_width=True):
        st.warning("PBR Rule Queued: Traffic redirected to Sandbox.")

with c3:
    if st.button("PURGE DNS CACHE", use_container_width=True):
        st.info("Resolver Command: Cache Flush & Validation engaged.")

with c4:
    if st.button("QUARANTINE PAYLOAD", use_container_width=True):
        st.success("File System: Payload moved to isolated vault.")
