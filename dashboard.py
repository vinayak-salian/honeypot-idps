import streamlit as st
import pandas as pd
from datetime import datetime
import pytz

# --- CONFIGURATION ---

RAW_URL = f"https://raw.githubusercontent.com/vinayak-salian/honeypot-idps/main/logs/"

st.set_page_config(page_title="IDPS Operational Console", page_icon="🛡️", layout="wide")

st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .stMetric { background-color: #1e2130; padding: 15px; border-radius: 10px; border: 1px solid #3e4250; }
    table { color: white; width: 100%; border-collapse: collapse; font-size: 14px; }
    th { text-align: left; padding: 10px; border-bottom: 1px solid #3e4250; background-color: #1e2130; }
    td { padding: 10px; border-bottom: 1px solid #3e4250; }
    </style>
    """, unsafe_allow_html=True)

ist = pytz.timezone('Asia/Kolkata')

@st.cache_data(ttl=60)
def fetch_logs(filename):
    """Fetches real logs only. Returns empty dataframe if no logs exist."""
    try:
        url = RAW_URL + filename
        return pd.read_csv(url)
    except Exception:
        return pd.DataFrame()

st.title("🛡️ IoT Autonomous Honeypot & IDPS")
st.markdown("### Operational Intelligence & Strategic Mitigation Console")

status_col, time_col = st.columns([3, 1])
ps_df = fetch_logs("portscan_log.csv")
mw_df = fetch_logs("malware_delivery_log.csv")
bf_df = fetch_logs("bruteforce_log.csv")
dns_df = fetch_logs("dns_spoof_log.csv")

with status_col:
    st.success("🟢 **SYSTEM STATUS:** SENTRY NODE OPERATIONAL (LIVE FEED ACTIVE)")

with time_col:
    st.write(f"**IST Time:** {datetime.now(ist).strftime('%H:%M:%S')}")

m1, m2, m3, m4 = st.columns(4)
m1.metric("RECONNAISSANCE EVENTS", len(ps_df))
m2.metric("PAYLOAD DROPS", len(mw_df))
m3.metric("AUTH VIOLATIONS", len(bf_df)) 
m4.metric("DNS ANOMALIES", len(dns_df))

st.markdown("---")
st.subheader("🚨 Real-Time Threat Intelligence Feed")
tab1, tab2, tab3, tab4 = st.tabs(["Port Scanning", "Malware Delivery", "Brute Force", "DNS Spoofing"])

with tab1: 
    if not ps_df.empty:
        html_table = ps_df.astype(str).sort_index(ascending=False).to_html(index=False, escape=False)
        st.markdown(html_table, unsafe_allow_html=True)
    else:
        st.info("No Port Scan logs found.")
        
with tab2: 
    if not mw_df.empty:
        html_table = mw_df.astype(str).sort_index(ascending=False).to_html(index=False, escape=False)
        st.markdown(html_table, unsafe_allow_html=True)
    else:
        st.info("No Malware logs found.")
        
with tab3: 
    if not bf_df.empty:
        html_table = bf_df.astype(str).sort_index(ascending=False).to_html(index=False, escape=False)
        st.markdown(html_table, unsafe_allow_html=True)
    else:
        st.info("No Brute Force logs found.")
    
with tab4: 
    if not dns_df.empty:
        html_table = dns_df.astype(str).sort_index(ascending=False).to_html(index=False, escape=False)
        st.markdown(html_table, unsafe_allow_html=True)
    else:
        st.info("No DNS Spoofing logs found.")

st.markdown("---")
st.subheader("⚡ Defense Mechanisms & Mitigation")
st.info("🤖 **AUTONOMOUS DEFENSE ACTIVE:** ML Engine is predicting threats and executing Policy-Based Routing on hostile IPs.")

st.markdown("#### 🛑 Autonomous Firewall Actions (Live Feed)")
try:
    blocked_df = pd.read_csv(RAW_URL + "blocked_ips.txt", names=["Banned Source IPs"])
    if not blocked_df.empty:
        st.table(blocked_df.astype(str))
    else:
        st.success("No IPs currently banned by the Sentry.")
except Exception:
    st.success("No IPs currently banned by the Sentry.")
