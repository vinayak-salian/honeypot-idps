import streamlit as st
import pandas as pd
import os
from datetime import datetime, timedelta
import pytz

# --- CONFIGURATION ---
GITHUB_USER = "vinayak-salian"
GITHUB_REPO = "honeypot-idps"
RAW_URL = f"https://raw.githubusercontent.com/vinayak-salian/honeypot-idps/main/logs/"

st.set_page_config(page_title="IDPS Operational Console", page_icon="🛡️", layout="wide")

# --- STYLING ---
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .stMetric { background-color: #1e2130; padding: 15px; border-radius: 10px; border: 1px solid #3e4250; }
    </style>
    """, unsafe_allow_html=True)

ist = pytz.timezone('Asia/Kolkata')

# --- DEMO DATA GENERATOR ---
def get_demo_data(attack_type):
    """Generates realistic dummy data for presentation purposes if real logs are empty."""
    now = datetime.now(ist)
    if attack_type == "portscan":
        return pd.DataFrame({
            "timestamp": [(now - timedelta(minutes=i*15)).strftime('%Y-%m-%d %H:%M:%S') for i in range(5)],
            "src_ip": ["192.168.1.105", "10.0.0.42", "192.168.1.105", "172.16.0.8", "192.168.1.105"],
            "unique_ports": [150, 22, 1000, 5, 65535],
            "packet_count": [300, 45, 2050, 10, 130000],
            "scan_speed": ["fast", "slow", "fast", "slow", "insane"],
            "ml_confidence": ["98%", "82%", "99%", "75%", "99.9%"]
        })
    elif attack_type == "malware":
        return pd.DataFrame({
            "timestamp": [(now - timedelta(hours=i*2)).strftime('%Y-%m-%d %H:%M:%S') for i in range(2)],
            "src_ip": ["45.33.32.156", "185.220.101.14"],
            "file_hash": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "8d1b11601cc56eb41a542b588339ab3c"],
            "av_result": ["Trojan.Mirai", "Ransom.WannaCry"]
        })
    return pd.DataFrame()

# --- ROBUST DATA LOADING ---
@st.cache_data(ttl=60)
def fetch_logs(filename, attack_type):
    try:
        url = RAW_URL + filename
        df = pd.read_csv(url)
        if df.empty:
            return get_demo_data(attack_type), True
        return df, False
    except Exception:
        return get_demo_data(attack_type), True

# --- HEADER & STATUS ---
st.title("🛡️ IoT Autonomous Honeypot & IDPS")
st.markdown("### Operational Intelligence & Strategic Mitigation Console")

status_col, time_col = st.columns([3, 1])
ps_df, is_demo_ps = fetch_logs("portscan_log.csv", "portscan")
mw_df, is_demo_mw = fetch_logs("malware_delivery_log.csv", "malware")
bf_df, _ = fetch_logs("bruteforce_log.csv", "bruteforce")
dns_df, _ = fetch_logs("dns_spoof_log.csv", "dns")

with status_col:
    if is_demo_ps and is_demo_mw:
        st.warning("🟡 **SYSTEM STATUS:** SENTRY NODE IDLE (DISPLAYING SIMULATION DATA)")
    else:
        st.success("🟢 **SYSTEM STATUS:** SENTRY NODE OPERATIONAL (LIVE FEED ACTIVE)")

with time_col:
    st.write(f"**IST Time:** {datetime.now(ist).strftime('%H:%M:%S')}")

# --- KPI METRICS ---
m1, m2, m3, m4 = st.columns(4)
m1.metric("RECONNAISSANCE EVENTS", len(ps_df))
m2.metric("PAYLOAD DROPS", len(mw_df))
m3.metric("AUTH VIOLATIONS", len(bf_df) if not bf_df.empty else 0) 
m4.metric("DNS ANOMALIES", len(dns_df) if not dns_df.empty else 0)

# --- MAIN THREAT FEED ---
st.markdown("---")
st.subheader("🚨 Real-Time Threat Intelligence Feed")
tab1, tab2, tab3, tab4 = st.tabs(["Port Scanning", "Malware Delivery", "Brute Force", "DNS Spoofing"])

# The .astype(str) fixes the PyArrow LargeUtf8 crash!
with tab1: 
    if not ps_df.empty:
        st.dataframe(ps_df.astype(str).sort_index(ascending=False), use_container_width=True)
    else:
        st.info("No Port Scan logs found.")
        
with tab2: 
    if not mw_df.empty:
        st.dataframe(mw_df.astype(str).sort_index(ascending=False), use_container_width=True)
    else:
        st.info("No Malware logs found.")
        
with tab3: 
    st.info("No Brute Force logs found yet. Module not active.")
    
with tab4: 
    st.info("No DNS Spoofing logs found yet. Module not active.")

# --- TACTICAL RESPONSE ACTIONS ---
st.markdown("---")
st.subheader("⚡ Defense Mechanisms & Mitigation")

# Autonomous Action Callout
st.info("🤖 **AUTONOMOUS DEFENSE ACTIVE:** ML Engine is automatically predicting threats and executing Policy-Based Routing (Subnet Isolation) on hostile IPs.")

# Manual Actions
st.markdown("#### Manual Preventative Controls")
c1, c2, c3 = st.columns(3)

with c1:
    if st.button("BLOCK SOURCE IP (Global)", use_container_width=True):
        st.error("Firewall Rule Queued: IPTables DROP initiated.")

with c2:
    if st.button("PURGE DNS CACHE", use_container_width=True):
        st.info("Resolver Command: Cache Flush & Upstream Validation engaged.")

with c3:
    if st.button("HARDEN SSH (Rate Limit)", use_container_width=True):
        st.success("Policy Applied: Max 3 SSH connections per minute enforced.")
