from github import Github
import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import pytz
import base64

# --- 1. CONFIGURATION ---
AWS_IP = "51.21.135.152" 
RAW_URL = "https://raw.githubusercontent.com/vinayak-salian/honeypot-idps/main/logs/"
ist = pytz.timezone('Asia/Kolkata')

st.set_page_config(page_title="Nexus Security Core", page_icon="🛡️", layout="wide")

# --- 2. LOG FETCHING FUNCTION ---
@st.cache_data(ttl=10)
def fetch_logs(filename):
    try:
        url = f"{RAW_URL}{filename}?t={datetime.now().timestamp()}"
        df = pd.read_csv(url)
        # Standardize column names to lowercase to prevent KeyErrors
        df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        return df
    except Exception:
        return pd.DataFrame()

def send_command(ip, action):
    try:
        g = Github(st.secrets["GITHUB_TOKEN"])
        repo = g.get_repo("vinayak-salian/honeypot-idps")
        file_path = "logs/action_queue.csv"
        
        # 404 FIX: Try to get file, if it fails, create it
        try:
            contents = repo.get_contents(file_path)
            existing_data = contents.decoded_content.decode()
        except Exception:
            # File doesn't exist, initialize it
            existing_data = "timestamp,ip,action\n"
            repo.create_file(file_path, "Initialize action queue", existing_data)
            contents = repo.get_contents(file_path)

        new_line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')},{ip},{action}\n"
        updated_content = existing_data + new_line
        
        repo.update_file(contents.path, f"C2-{action}: {ip}", updated_content, contents.sha)
        st.success(f"Successfully queued {action} for {ip}")
    except Exception as e:
        st.error(f"Failed to send command: {e}")

# --- 3. DATA ACQUISITION ---
health_df = fetch_logs("system_status.csv")
events_df = fetch_logs("security_events.csv")
devices_df = fetch_logs("known_devices.csv")
traffic_df = fetch_logs("traffic_metrics.csv")
banned_df = fetch_logs("banned_ips.csv")

# Ensure column naming is consistent for filtering
if not banned_df.empty:
    banned_df.columns = ['banned_ip', 'timestamp', 'reason'] # Force standard names

# --- 4. MITIGATION PLAYBOOK ---
PLAYBOOK = {
    "portscan": {"solution": "Action: Deploy IPTables DROP rule for source. Enable rate-limiting."},
    "malware": {"solution": "Action: Isolate asset. Run ClamAV scan. Block outgoing C2."},
    "brute_force": {"solution": "Action: Enforce SSH Key Auth. Install Fail2Ban."},
    "dns_spoof": {"solution": "Action: Flush DNS cache. Enforce DNSSEC."}
}

# --- 5. CUSTOM CSS ---
st.markdown("""
<style>
    .stApp { background-color: #050505; color: #e2e8f0; }
    .main-header { font-size: 2.2rem; background: linear-gradient(90deg, #3b82f6, #ec4899); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: 700; margin-bottom: 5px; }
    .playbook-card { background: rgba(59, 130, 246, 0.1); border-left: 5px solid #3b82f6; padding: 15px; border-radius: 5px; margin-bottom: 10px; font-size: 0.9rem; }
    [data-testid="stMetricValue"] { font-family: 'Fira Code', monospace; font-size: 1.6rem; color: #3b82f6; }
</style>
""", unsafe_allow_html=True)

# --- 6. SIDEBAR & HEADER ---
st.sidebar.title("🎮 Command Center")
op_mode = st.sidebar.radio("Select Mode:", ["Mode A: Global Watchtower", "Mode B: Local Sentinel"])

c_h1, c_h2 = st.columns([1.8, 1.2])
with c_h1:
    st.markdown('<div class="main-header">Nexus Security Core</div>', unsafe_allow_html=True)
with c_h2:
    if not health_df.empty:
        st.metric("Pi Gateway", f"🌐 {health_df.iloc[-1].get('gateway_ip', '--')}")

st.divider()

# --- MODE B: LOCAL SENTINEL ---
if op_mode == "Mode B: Local Sentinel":
    st.markdown("### 📱 Local Sentinel & Infection Zone")

    if not devices_df.empty:
        col_l, col_r = st.columns([1, 1.2])
        
        with col_l:
            st.markdown("**Discovered Local Assets**")
            selected_ip = st.selectbox("🎯 Select Target Device:", options=devices_df['ip_address'].unique())
            st.dataframe(devices_df, use_container_width=True, hide_index=True)
        
        with col_r:
            st.markdown(f"#### 🔍 Deep Inspection: {selected_ip}")
            
            # --- FEATURE 1: SMART TOGGLE BLOCK BUTTON ---
            is_banned = False
            if not banned_df.empty:
                is_banned = selected_ip in banned_df['banned_ip'].values

            btn_col, tel_col = st.columns(2)
            
            with btn_col:
                if is_banned:
                    if st.button(f"🔓 Manual Unblock {selected_ip}", type="primary", use_container_width=True):
                        send_command(selected_ip, "UNBLOCK")
                else:
                    if st.button(f"🚫 Permanent Block {selected_ip}", use_container_width=True):
                        send_command(selected_ip, "BLOCK")

            # --- FEATURE 2: RAW TELEMETRY BUTTON ---
            with tel_col:
                show_telemetry = st.button("📊 View Raw Telemetry", use_container_width=True)

            if show_telemetry:
                st.info(f"Fetching real-time packet telemetry for {selected_ip}...")
                # Note: This filters the traffic_df we fetched earlier
                if not traffic_df.empty:
                    st.dataframe(traffic_df, use_container_width=True)
                else:
                    st.warning("No raw telemetry data available for this cycle.")
            
            st.divider()
            
            # --- HOSTILE HISTORY ---
            st.markdown("##### 🔴 Hostile History")
            if not events_df.empty and 'source_ip' in events_df.columns:
                ip_events = events_df[events_df['source_ip'] == selected_ip]
                if not ip_events.empty:
                    st.warning(f"Detected {len(ip_events)} malicious signatures.")
                    st.dataframe(ip_events[['timestamp', 'attack_type', 'evidence', 'confidence']], use_container_width=True, hide_index=True)
                else: 
                    st.success("Clean: No hostile behavior found.")
    else:
        st.info("📡 Scanning Local Network... Connect a device to begin.")

# --- 7. LIVE THREAT INTELLIGENCE (Always Visible) ---
st.divider()
st.markdown("### 📡 Live Threat Intelligence")
tab1, tab2, tab3 = st.tabs(["🎯 Port Scans", "🔑 Brute Force", "🚫 Banned List"])

with tab1:
    if not events_df.empty:
        scan_data = events_df[events_df['attack_type'].str.contains('portscan|scan', case=False, na=False)]
        st.dataframe(scan_data, use_container_width=True, hide_index=True)
with tab2:
    if not events_df.empty:
        brute_data = events_df[events_df['attack_type'].str.contains('brute|ssh', case=False, na=False)]
        st.dataframe(brute_data, use_container_width=True, hide_index=True)
with tab3:
    if not banned_df.empty:
        st.dataframe(banned_df, use_container_width=True, hide_index=True)
    else:
        st.info("🛡️ No active IP bans.")
