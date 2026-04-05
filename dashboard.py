import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime
import pytz
from github import Github

# --- CONFIGURATION ---
RAW_URL = "https://raw.githubusercontent.com/vinayak-salian/honeypot-idps/main/logs/"

st.set_page_config(page_title="Nexus Security Core", page_icon="🛡️", layout="wide")

# --- MITIGATION PLAYBOOK (The "Solutions" you asked for) ---
PLAYBOOK = {
    "PortScan": {
        "label": "🎯 Port Scanning Detected",
        "solution": "Immediate Action: Deploy IPTables DROP rule for the source IP. Enable rate-limiting on edge firewall. Check for open services that shouldn't be public.",
        "severity": "Medium"
    },
    "Malware": {
        "label": "🦠 Malware Activity",
        "solution": "Immediate Action: Isolate the infected asset from the LAN. Run a filesystem scan (ClamAV). Check for outgoing connections to known C2 (Command & Control) IPs.",
        "severity": "Critical"
    },
    "Brute Force": {
        "label": "🔑 Brute Force / SSH Attack",
        "solution": "Immediate Action: Enforce Public-Key Authentication only. Install Fail2Ban on the target server. Alert admin to reset credentials if attempt was successful.",
        "severity": "High"
    },
    "DNS_Spoof": {
        "label": "📡 DNS Spoofing / Poisoning",
        "solution": "Immediate Action: Flush DNS cache on the Pi and clients. Enforce DNSSEC. Use static ARP tables for the Gateway to prevent ARP poisoning leading to DNS redirection.",
        "severity": "Critical"
    }
}

# --- CUSTOM CSS ---
st.markdown("""
<style>
    .stApp { background-color: #050505; color: #e2e8f0; }
    .main-header { font-size: 2.2rem; background: linear-gradient(90deg, #3b82f6, #ec4899); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: 700; }
    .playbook-card { background: rgba(59, 130, 246, 0.1); border-left: 5px solid #3b82f6; padding: 15px; border-radius: 5px; margin-bottom: 10px; }
</style>
""", unsafe_allow_html=True)

ist = pytz.timezone('Asia/Kolkata')

@st.cache_data(ttl=10)
def fetch_logs(filename):
    try:
        url = f"{RAW_URL}{filename}?t={datetime.now().timestamp()}"
        df = pd.read_csv(url)
        return df
    except:
        return pd.DataFrame()

# Data Fetching
events_df = fetch_logs("security_events.csv")
devices_df = fetch_logs("known_devices.csv")
traffic_df = fetch_logs("traffic_metrics.csv")
banned_df = fetch_logs("banned_ips.csv")

# --- HEADER ---
st.markdown('<div class="main-header">Nexus Security Core v2.2.0</div>', unsafe_allow_html=True)
st.markdown(f"🟢 C2 CLOUD NODE ONLINE | {datetime.now(ist).strftime('%H:%M:%S IST')}")
st.divider()

# --- TOP: NETWORK CENSUS & INVESTIGATION ---
st.markdown("### 📱 Active Network Census")
if not devices_df.empty:
    col_l, col_r = st.columns([1, 1])
    with col_l:
        st.markdown("**Discovered Local Assets**")
        selected_ip = st.selectbox("🎯 Select Device for Traffic Inspection:", options=devices_df['ip_address'].unique())
        st.dataframe(devices_df, use_container_width=True, hide_index=True)
    
    with col_r:
        st.markdown(f"#### 🔍 Deep Inspection: {selected_ip}")
        t_events, t_traffic = st.tabs(["🔴 Hostile History", "📊 Raw Telemetry"])
        
        with t_events:
            if not events_df.empty and selected_ip in events_df['source_ip'].values:
                ip_events = events_df[events_df['source_ip'] == selected_ip]
                st.warning(f"Detected {len(ip_events)} malicious signatures.")
                st.dataframe(ip_events, use_container_width=True, hide_index=True)
            else:
                st.success("No hostile behavior found.")

        with t_traffic:
            # FIX: Keyerror Safety Check
            if not traffic_df.empty and 'source_ip' in traffic_df.columns:
                asset_traffic = traffic_df[traffic_df['source_ip'] == selected_ip]
                if not asset_traffic.empty:
                    st.dataframe(asset_traffic, use_container_width=True, hide_index=True)
                else:
                    st.info("Device is silent. No active packets recorded.")
            else:
                st.info("Telemetry log empty. Ensure Sentry is in traffic-sniffing mode.")

st.divider()

# --- MIDDLE: THREAT INTELLIGENCE & SOLUTIONS ---
st.markdown("### 📡 Real-Time Threat Intel & Mitigation")
tab1, tab2, tab3, tab4, tab5 = st.tabs(["🎯 Port Scans", "🦠 Malware", "🔑 Brute Force", "🌐 DNS Security", "🚫 Banned List"])

def display_with_solution(df, attack_key):
    if not df.empty:
        st.dataframe(df, use_container_width=True, hide_index=True)
        # Display the Solution Playbook
        if attack_key in PLAYBOOK:
            st.markdown(f"""
            <div class="playbook-card">
                <strong>🛡️ Recommended Response for {PLAYBOOK[attack_key]['label']}:</strong><br>
                {PLAYBOOK[attack_key]['solution']}
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info(f"System status clear for {attack_key} signatures.")

with tab1:
    display_with_solution(events_df[events_df['attack_type'].str.contains('PortScan', na=False)] if not events_df.empty else pd.DataFrame(), "PortScan")
with tab2:
    display_with_solution(events_df[events_df['attack_type'].str.contains('Malware', na=False)] if not events_df.empty else pd.DataFrame(), "Malware")
with tab3:
    display_with_solution(events_df[events_df['attack_type'].str.contains('Brute', na=False)] if not events_df.empty else pd.DataFrame(), "Brute Force")
with tab4:
    # WHERE IS DNS? -> We look for DNS-related attack types here
    dns_events = events_df[events_df['attack_type'].str.contains('DNS|Spoof', na=False)] if not events_df.empty else pd.DataFrame()
    display_with_solution(dns_events, "DNS_Spoof")
with tab5:
    if not banned_df.empty: st.dataframe(banned_df, use_container_width=True)

st.divider()

# --- BOTTOM: GLOBAL ATTRIBUTION ---
st.markdown("### 📜 Global Attribution Map")
if not events_df.empty and 'latitude' in events_df.columns:
    st.map(events_df.dropna(subset=['latitude', 'longitude']), latitude='latitude', longitude='longitude', color='#ec4899', size=40)

st.markdown("<center style='color: #475569;'>Nexus System Build v2.2.0 • Playbook Integration Active</center>", unsafe_allow_html=True)
