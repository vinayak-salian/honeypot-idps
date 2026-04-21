from github import Github
import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import pytz
import time

# --- 1. CONFIGURATION ---
AWS_IP = "51.21.135.152" 
# Use a custom header/param to attempt to bypass GitHub CDN
RAW_URL = "https://raw.githubusercontent.com/vinayak-salian/honeypot-idps/main/logs/"
ist = pytz.timezone('Asia/Kolkata')

st.set_page_config(page_title="Nexus Security Core", page_icon="🛡️", layout="wide")

# --- 2. LOG FETCHING FUNCTION (WITH CACHE BUSTER) ---
@st.cache_data(ttl=5) # Reduced TTL for snappier demo response
def fetch_logs(filename):
    try:
        # The 'nocache' parameter helps bypass GitHub's 5-minute raw cache
        url = f"{RAW_URL}{filename}?nocache={int(time.time())}"
        df = pd.read_csv(url)
        
        # COLUMN SAFETY: Force 9 columns to prevent Pandas crashes if detectors send 10
        expected_cols = ['timestamp', 'source_ip', 'attack_type', 'confidence', 'evidence', 'latitude', 'longitude', 'country', 'city']
        if filename == "security_events.csv" or filename == "local_events.csv":
            if len(df.columns) > 9:
                df = df.iloc[:, :9]
            df.columns = expected_cols[:len(df.columns)]

        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        return df
    except Exception:
        return pd.DataFrame()

def send_command(ip, action):
    try:
        # Use st.secrets for token safety
        g = Github(st.secrets["GITHUB_TOKEN"])
        repo = g.get_repo("vinayak-salian/honeypot-idps")
        file_path = "logs/action_queue.csv"
        
        try:
            contents = repo.get_contents(file_path)
            existing_data = contents.decoded_content.decode()
        except:
            existing_data = "timestamp,ip,action\n"
            repo.create_file(file_path, "Initialize action queue", existing_data)
            contents = repo.get_contents(file_path)
        
        new_line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')},{ip},{action}\n"
        updated_content = existing_data + new_line
        
        repo.update_file(contents.path, f"C2-Command: {action} {ip}", updated_content, contents.sha)
        st.success(f"Command '{action}' sent to GitHub.")
        # Clear cache immediately so the UI reflects the change
        st.cache_data.clear()
    except Exception as e:
        st.error(f"Failed to send command: {e}")

# --- 3. DATA ACQUISITION ---
health_df = fetch_logs("system_status.csv")
global_events_df = fetch_logs("security_events.csv")
local_events_df = fetch_logs("local_events.csv")
devices_df = fetch_logs("known_devices.csv")
traffic_df = fetch_logs("traffic_metrics.csv")
banned_df = fetch_logs("banned_ips.csv")
web_df = fetch_logs("web_history.csv") 

# Fix for IST timestamps on devices
if not devices_df.empty and 'last_seen' in devices_df.columns:
    devices_df['last_seen'] = pd.to_datetime(devices_df['last_seen'], errors='coerce')
    devices_df['last_seen'] = devices_df['last_seen'].dt.strftime('%H:%M:%S IST')

# --- 4. PLAYBOOK & CSS ---
PLAYBOOK = {
    "PortScan": {"label": "🎯 Port Scanning", "solution": "Action: Deploy IPTables DROP rule. Enable rate-limiting."},
    "Malware": {"label": "🦠 Malware Activity", "solution": "Action: Isolate asset. Block outgoing C2 connections."},
    "Brute Force": {"label": "🔑 Brute Force", "solution": "Action: Install Fail2Ban. Reset SSH credentials."},
    "DNS_Tunneling": {"label": "📡 DNS Tunneling", "solution": "Action: Isolate device. Detects encoded data in DNS queries."}
}

st.markdown("""
<style>
    .stApp { background-color: #050505; color: #e2e8f0; }
    .main-header { font-size: 2.2rem; background: linear-gradient(90deg, #3b82f6, #ec4899); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: 700; }
    .status-online { color: #10b981; background: rgba(16, 185, 129, 0.1); padding: 5px 15px; border-radius: 20px; border: 1px solid #10b981; font-size: 0.8rem; }
    .status-offline { color: #ef4444; background: rgba(239, 68, 68, 0.1); padding: 5px 15px; border-radius: 20px; border: 1px solid #ef4444; font-size: 0.8rem; }
</style>
""", unsafe_allow_html=True)

# --- 5. SIDEBAR ---
st.sidebar.title("🎮 Command Center")
if st.sidebar.button("🔄 Force Global Refresh"):
    st.cache_data.clear()
    st.rerun()
op_mode = st.sidebar.radio("Select Operational Mode:", ["Mode A: Global Watchtower", "Mode B: Local Sentinel"])

# --- 6. HEADER ---
c_h1, c_h2 = st.columns([1.8, 1.2])

with c_h1:
    st.markdown('<div class="main-header">Nexus Security Core</div>', unsafe_allow_html=True)
    is_online = False
    last_sync_str = "No Heartbeat Detected"
    if not health_df.empty:
        latest = health_df.iloc[-1]
        last_sync = latest['timestamp']
        if pd.notnull(last_sync):
            last_sync_ist = ist.localize(last_sync.replace(tzinfo=None))
            now_ist = datetime.now(ist)
            diff = (now_ist - last_sync_ist).total_seconds()
            # If sync was in the last 3 minutes, show Online
            if diff < 180: is_online = True
            last_sync_str = last_sync_ist.strftime('%H:%M:%S IST')
    
    s_class = "status-online" if is_online else "status-offline"
    s_text = f"🟢 PI NODE ACTIVE | Pulse: {last_sync_str}" if is_online else f"🔴 PI NODE OFFLINE | Sync Gap: {int(diff/60) if 'diff' in locals() else '??'}m"
    st.markdown(f'<span class="{s_class}">{s_text}</span>', unsafe_allow_html=True)

with c_h2:
    m1, m2 = st.columns(2)
    uptime_val = health_df.iloc[-1].get('uptime', '0h 0m') if not health_df.empty else "--"
    m1.metric("Uptime", f"⏱️ {uptime_val}")
    m2.metric("Gateway", f"🌐 {health_df.iloc[-1].get('gateway_ip', '--') if not health_df.empty else '--'}")

st.divider()

# --- 7. MODE SECTIONS ---
if op_mode == "Mode A: Global Watchtower":
    active_events_df = global_events_df[global_events_df['attack_type'] != 'Benign'] if not global_events_df.empty else pd.DataFrame()
    st.markdown("### 🌐 Global Threat Intelligence (AWS Feed)")
    col_map, col_hist = st.columns([1.2, 1])
    with col_map:
        if not active_events_df.empty and 'latitude' in active_events_df.columns:
            st.map(active_events_df.dropna(subset=['latitude', 'longitude']), color='#ec4899', size=40)
        else: st.info("📡 Awaiting global telemetry...")
    with col_hist:
        st.dataframe(active_events_df.sort_values("timestamp", ascending=False), height=400, use_container_width=True, hide_index=True)

else:
    # MODE B: LOCAL SENTINEL
    # FILTER: Remove Benign logs from the local demo feed
    active_events_df = local_events_df[local_events_df['attack_type'] != 'Benign'] if not local_events_df.empty else pd.DataFrame()
    
    st.markdown("### 📱 Local Sentinel (Raspberry Pi)")
    if not health_df.empty and not devices_df.empty:
        selected_ip = st.selectbox("🎯 Select Target Device:", options=devices_df['ip_address'].unique())
        
        col_l, col_r = st.columns([1, 1.2])
        with col_l:
            st.dataframe(devices_df, use_container_width=True, hide_index=True)
        
        with col_r:
            st.markdown(f"#### 🔍 Deep Inspection: {selected_ip}")
            
            # Action Buttons
            c_block, c_web = st.columns(2)
            with c_block:
                is_banned = selected_ip in banned_df['ip'].values if not banned_df.empty else False
                if is_banned:
                    if st.button(f"🔓 RESTORE ACCESS", type="primary", use_container_width=True):
                        send_command(selected_ip, "UNBLOCK")
                        st.rerun()
                else:
                    if st.button(f"🚫 ISOLATE ASSET", use_container_width=True):
                        send_command(selected_ip, "BLOCK")
                        st.rerun()

            show_web = st.toggle("🌐 View Browsing History")
            if show_web:
                user_history = web_df[web_df['source_ip'].astype(str) == str(selected_ip)]
                if not user_history.empty: st.table(user_history[['timestamp', 'domain']].head(10))
                else: st.info("No browsing history found.")

            st.markdown("##### 🔴 Hostile History (Detected Attacks)")
            ip_events = active_events_df[active_events_df['source_ip'].astype(str) == str(selected_ip)]
            if not ip_events.empty:
                st.dataframe(ip_events[['timestamp', 'attack_type', 'evidence', 'confidence']], use_container_width=True, hide_index=True)
            else: st.success("No hostile behavior found in this session.")

# --- 8. LIVE THREAT INTELLIGENCE (TABS) ---
st.divider()
st.markdown("### 📡 Live Threat Intelligence")
tabs = st.tabs(["🎯 Port Scans", "🦠 Malware", "🔑 Brute Force", "🌐 DNS Security", "🚫 Banned List"])

def filter_tab(df, attack_patterns):
    if df.empty: return pd.DataFrame()
    return df[df['attack_type'].str.contains(attack_patterns, na=False)]

with tabs[0]: st.dataframe(filter_tab(active_events_df, 'PortScan|Scan'), use_container_width=True)
with tabs[1]: st.dataframe(filter_tab(active_events_df, 'Malware'), use_container_width=True)
with tabs[2]: st.dataframe(filter_tab(active_events_df, 'Brute|SSH'), use_container_width=True)
with tabs[3]: st.dataframe(filter_tab(active_events_df, 'DNS|Tunnel'), use_container_width=True)
with tabs[4]: st.dataframe(banned_df, use_container_width=True)
