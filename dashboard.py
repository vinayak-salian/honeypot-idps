import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import pytz

# --- 1. CONFIGURATION ---
AWS_IP = "51.21.135.152" 
RAW_URL = "https://raw.githubusercontent.com/vinayak-salian/honeypot-idps/main/logs/"
ist = pytz.timezone('Asia/Kolkata')

st.set_page_config(page_title="Nexus Security Core", page_icon="🛡️", layout="wide")

# --- 2. LOG FETCHING FUNCTION ---
@st.cache_data(ttl=10)
def fetch_logs(filename):
    try:
        # Cache-busting URL to ensure fresh data
        url = f"{RAW_URL}{filename}?t={datetime.now().timestamp()}"
        df = pd.read_csv(url)
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        return df
    except Exception:
        return pd.DataFrame()

# --- 3. DATA ACQUISITION ---
health_df = fetch_logs("system_status.csv")
events_df = fetch_logs("security_events.csv")
devices_df = fetch_logs("known_devices.csv")
traffic_df = fetch_logs("traffic_metrics.csv")
banned_df = fetch_logs("banned_ips.csv")

# --- 4. MITIGATION PLAYBOOK ---
PLAYBOOK = {
    "PortScan": {
        "label": "🎯 Port Scanning Detected",
        "solution": "Action: Deploy IPTables DROP rule for source. Enable rate-limiting on edge firewall.",
    },
    "Malware": {
        "label": "🦠 Malware Activity",
        "solution": "Action: Isolate asset. Run ClamAV scan. Block outgoing C2 connections.",
    },
    "Brute Force": {
        "label": "🔑 Brute Force / SSH Attack",
        "solution": "Action: Enforce SSH Key Auth. Install Fail2Ban. Reset credentials.",
    },
    "DNS_Spoof": {
        "label": "📡 DNS Spoofing / Poisoning",
        "solution": "Action: Flush DNS cache (sudo systemd-resolve --flush-caches). Enforce DNSSEC.",
    }
}

# --- 5. CUSTOM CSS ---
st.markdown("""
<style>
    .stApp { background-color: #050505; color: #e2e8f0; }
    .main-header { font-size: 2.2rem; background: linear-gradient(90deg, #3b82f6, #ec4899); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: 700; margin-bottom: 5px; }
    .status-online { color: #10b981; background: rgba(16, 185, 129, 0.1); padding: 5px 15px; border-radius: 20px; border: 1px solid #10b981; font-size: 0.8rem; }
    .status-offline { color: #ef4444; background: rgba(239, 68, 68, 0.1); padding: 5px 15px; border-radius: 20px; border: 1px solid #ef4444; font-size: 0.8rem; }
    .playbook-card { background: rgba(59, 130, 246, 0.1); border-left: 5px solid #3b82f6; padding: 15px; border-radius: 5px; margin-bottom: 10px; font-size: 0.9rem; }
    [data-testid="stMetricValue"] { font-family: 'Fira Code', monospace; font-size: 1.6rem; color: #3b82f6; }
</style>
""", unsafe_allow_html=True)

# --- 6. SIDEBAR MODE TOGGLE ---
st.sidebar.title("🎮 Command Center")
op_mode = st.sidebar.radio(
    "Select Operational Mode:",
    ["Mode A: Global Watchtower", "Mode B: Local Sentinel"]
)

# --- 7. HEADER & DYNAMIC METRICS ---
c_h1, c_h2 = st.columns([1.8, 1.2])

with c_h1:
    st.markdown('<div class="main-header">Nexus Security Core</div>', unsafe_allow_html=True)
    
    is_online = False
    last_sync_str = "Awaiting Heartbeat..."
    
    if not health_df.empty:
        latest = health_df.iloc[-1]
        last_sync = latest['timestamp']
        
        if pd.notnull(last_sync):
            # Localize to IST
            last_sync_ist = ist.localize(last_sync.replace(tzinfo=None))
            now_ist = datetime.now(ist)
            diff = (now_ist - last_sync_ist).total_seconds()
            
            if diff < 900: is_online = True
            last_sync_str = last_sync_ist.strftime('%H:%M:%S IST')

    s_class = "status-online" if is_online else "status-offline"
    s_text = f"🟢 PI NODE ACTIVE | Pulse: {last_sync_str}" if is_online else f"🔴 PI NODE OFFLINE | Pulse: {last_sync_str}"
    st.markdown(f'<span class="{s_class}">{s_text}</span>', unsafe_allow_html=True)

with c_h2:
    m1, m2 = st.columns(2)
    if not health_df.empty:
        latest = health_df.iloc[-1]
        
        # 1. Clean Uptime (Short format: 1h 20m)
        uptime_display = latest.get('uptime', '0h 0m')
        
        # 2. Mode-Based Gateway
        if op_mode == "Mode A: Global Watchtower":
            gateway_display = AWS_IP
            label = "Cloud IP"
        else:
            gateway_display = latest.get('gateway_ip', 'Detecting...')
            label = "Pi Gateway"
            
        m1.metric("Uptime", f"⏱️ {uptime_display}")
        m2.metric(label, f"🌐 {gateway_display}")
    else:
        m1.metric("Uptime", "⏱️ --")
        m2.metric("Gateway", "🌐 --")

st.divider()

# --- MODE A: GLOBAL WATCHTOWER ---
if op_mode == "Mode A: Global Watchtower":
    st.markdown("### 🌐 Global Threat Intelligence & Research")
    col_map, col_hist = st.columns([1.2, 1])

    with col_map:
        st.markdown("#### Real-Time Attack Heatmap")
        # Check if we have valid coordinates to map
        if not events_df.empty and 'latitude' in events_df.columns and not events_df['latitude'].isnull().all():
            st.map(events_df.dropna(subset=['latitude', 'longitude']), latitude='latitude', longitude='longitude', color='#ec4899', size=40)
        else:
            st.info("📡 System Ready. Awaiting global telemetry from AWS VPS...")

    with col_hist:
        st.markdown("#### Historical Botnet Archive")
        if not events_df.empty and len(events_df) > 1: # len > 1 because header-only is len 1 or empty
            st.dataframe(events_df.sort_values("timestamp", ascending=False), height=450, use_container_width=True, hide_index=True)
        else:
            st.info("🗄️ Archive currently empty. Fresh logs will appear here.")

# --- MODE B: LOCAL SENTINEL ---
else:
    st.markdown("### 📱 Local Sentinel & Infection Zone")
    
    # 1. Network Census Section
    # Check if we have actual data beyond just the header
    if not devices_df.empty:
        col_l, col_r = st.columns([1, 1.2])
        with col_l:
            st.markdown("**Discovered Local Assets**")
            selected_ip = st.selectbox("🎯 Select Target Device:", options=devices_df['ip_address'].unique())
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
                    st.success("Clean: No hostile behavior found for this asset.")
            with t_traffic:
                if not traffic_df.empty and 'source_ip' in traffic_df.columns:
                    asset_traffic = traffic_df[traffic_df['source_ip'] == selected_ip]
                    if not asset_traffic.empty: st.dataframe(asset_traffic, use_container_width=True, hide_index=True)
                    else: st.info("Asset is currently silent.")
                else: st.info("No raw telemetry captured yet.")
    else:
        st.info("📡 Scanning Local Network... Connect a device to the Sentry AP to begin.")
    
    st.divider()

    # 2. Distinct Sections for the 4 Attack Types
    st.markdown("### 📡 Live Threat Intelligence")
    
    def display_section(df, attack_key):
        if not df.empty and len(df) > 0:
            st.dataframe(df, use_container_width=True, hide_index=True)
            if attack_key in PLAYBOOK:
                st.markdown(f'<div class="playbook-card"><strong>🛡️ Mitigation:</strong> {PLAYBOOK[attack_key]["solution"]}</div>', unsafe_allow_html=True)
        else:
            st.info(f"✅ System status clear for {attack_key}.")

    tab1, tab2, tab3, tab4, tab5 = st.tabs(["🎯 Port Scans", "🦠 Malware", "🔑 Brute Force", "🌐 DNS Security", "🚫 Banned List"])

    with tab1:
        scan_data = events_df[events_df['attack_type'].str.contains('PortScan|Heartbeat', na=False)] if not events_df.empty else pd.DataFrame()
        display_section(scan_data, "PortScan")
    with tab2:
        mal_data = events_df[events_df['attack_type'].str.contains('Malware', na=False)] if not events_df.empty else pd.DataFrame()
        display_section(mal_data, "Malware")
    with tab3:
        brute_data = events_df[events_df['attack_type'].str.contains('Brute', na=False)] if not events_df.empty else pd.DataFrame()
        display_section(brute_data, "Brute Force")
    with tab4:
        dns_data = events_df[events_df['attack_type'].str.contains('DNS|Spoof', na=False)] if not events_df.empty else pd.DataFrame()
        display_section(dns_data, "DNS_Spoof")
    with tab5:
        if not banned_df.empty: st.dataframe(banned_df, use_container_width=True, hide_index=True)
        else: st.info("🛡️ No active IP bans in the local kernel.")

st.markdown("<center style='color: #475569; padding-top: 30px;'>Nexus System Build v2.5.1 </center>", unsafe_allow_html=True)
