from github import Github
import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime
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
        url = f"{RAW_URL}{filename}?t={datetime.now().timestamp()}"
        df = pd.read_csv(url)
        # Standardize column names to prevent KeyErrors
        df.columns = [c.strip() for c in df.columns]
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        return df
    except Exception:
        return pd.DataFrame()

def send_command(ip, action):
    try:
        # Ensure GITHUB_TOKEN is set in Streamlit Secrets
        g = Github(st.secrets["GITHUB_TOKEN"])
        repo = g.get_repo("vinayak-salian/honeypot-idps")
        contents = repo.get_contents("logs/action_queue.csv")
        
        new_line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')},{ip},{action}\n"
        updated_content = contents.decoded_content.decode() + new_line
        
        repo.update_file(contents.path, f"C2-Command: {action} {ip}", updated_content, contents.sha)
        st.success(f"Command '{action}' queued for {ip}")
    except Exception as e:
        st.error(f"GitHub Auth Error: Ensure GITHUB_TOKEN is in Secrets. Detail: {e}")

# --- 3. DATA ACQUISITION ---
events_df = fetch_logs("security_events.csv")
devices_df = fetch_logs("known_devices.csv")
traffic_df = fetch_logs("traffic_metrics.csv")
banned_df = fetch_logs("banned_ips.csv")
health_df = fetch_logs("system_status.csv")

# --- 4. CUSTOM CSS ---
st.markdown("""
<style>
    .stApp { background-color: #050505; color: #e2e8f0; }
    .main-header { font-size: 2.2rem; background: linear-gradient(90deg, #3b82f6, #ec4899); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: 700; }
    .status-online { color: #10b981; border: 1px solid #10b981; padding: 5px 10px; border-radius: 10px; }
    [data-testid="stMetricValue"] { color: #3b82f6; }
</style>
""", unsafe_allow_html=True)

# --- 5. SIDEBAR & HEADER ---
st.sidebar.title("🎮 Command Center")
op_mode = st.sidebar.radio("Select Operational Mode:", ["Global Watchtower", "Local Sentinel"])

st.markdown('<div class="main-header">Nexus Security Core</div>', unsafe_allow_html=True)

# --- 6. MODE B: LOCAL SENTINEL (The Interactive Demo) ---
if op_mode == "Local Sentinel":
    st.markdown("### 📱 Local Sentinel & Infection Zone")

    if not devices_df.empty and 'ip_address' in devices_df.columns:
        col_l, col_r = st.columns([1, 1.2])
        
        with col_l:
            st.markdown("**Discovered Local Assets**")
            selected_ip = st.selectbox("🎯 Select Target Device:", options=devices_df['ip_address'].unique())
            st.dataframe(devices_df, use_container_width=True, hide_index=True)
        
        with col_r:
            st.markdown(f"#### 🔍 Deep Inspection: {selected_ip}")
            
            # --- SMART TOGGLE BUTTON ---
            # Check if current selected IP is in the banned list
            is_banned = False
            if not banned_df.empty and 'Banned IP' in banned_df.columns:
                is_banned = selected_ip in banned_df['Banned IP'].values

            if is_banned:
                if st.button(f"🔓 Manual Unblock {selected_ip}", type="primary", use_container_width=True):
                    send_command(selected_ip, "UNBLOCK")
            else:
                if st.button(f"🚫 Permanent Block {selected_ip}", type="secondary", use_container_width=True):
                    send_command(selected_ip, "BLOCK")
            
            # --- HOSTILE HISTORY ---
            st.markdown("---")
            t_events, t_traffic = st.tabs(["🔴 Hostile History", "📊 Raw Telemetry"])
            
            with t_events:
                if not events_df.empty and 'source_ip' in events_df.columns:
                    ip_events = events_df[events_df['source_ip'] == selected_ip]
                    if not ip_events.empty:
                        st.warning(f"Detected {len(ip_events)} malicious signatures from this asset.")
                        st.dataframe(ip_events[['timestamp', 'attack_type', 'evidence', 'confidence']], use_container_width=True, hide_index=True)
                    else:
                        st.success("Clean: No hostile behavior found for this asset.")
                else:
                    st.info("Awaiting telemetry logs...")
    else:
        st.info("📡 Scanning Local Network... Connect a device to the Sentry AP to begin.")

# --- 7. LIVE THREAT INTELLIGENCE (Bottom Tables) ---
st.divider()
st.markdown("### 📡 Global Threat Intelligence")
tab1, tab2, tab3 = st.tabs(["🎯 Port Scans", "🔑 Brute Force", "🚫 Banned List"])

with tab1:
    if not events_df.empty:
        scan_data = events_df[events_df['attack_type'].str.contains('PortScan|Scan', na=False)]
        st.dataframe(scan_data, use_container_width=True, hide_index=True)
    else: st.info("No scan data detected.")

with tab2:
    if not events_df.empty:
        brute_data = events_df[events_df['attack_type'].str.contains('Brute|SSH|Login', na=False)]
        st.dataframe(brute_data, use_container_width=True, hide_index=True)
    else: st.info("No brute force attempts detected.")

with tab3:
    if not banned_df.empty:
        st.dataframe(banned_df, use_container_width=True, hide_index=True)
    else: st.info("No active IP bans.")
