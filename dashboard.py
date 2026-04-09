from github import Github
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
        url = f"{RAW_URL}{filename}?t={datetime.now().timestamp()}"
        df = pd.read_csv(url)
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
        
        # FIX: 404 Safety check. Get file, or create it if missing.
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
        st.success(f"Command '{action}' queued for {ip}")
    except Exception as e:
        st.error(f"Failed to send command: {e}")

# --- 3. DATA ACQUISITION ---
health_df = fetch_logs("system_status.csv")
events_df = fetch_logs("security_events.csv")
devices_df = fetch_logs("known_devices.csv")
traffic_df = fetch_logs("traffic_metrics.csv")
banned_df = fetch_logs("banned_ips.csv")
web_df = fetch_logs("web_history.csv") # Fetched for the browsing history feature

if not devices_df.empty and 'last_seen' in devices_df.columns:
    devices_df['last_seen'] = pd.to_datetime(devices_df['last_seen'], errors='coerce')
    devices_df['last_seen'] = devices_df['last_seen'].dt.tz_localize('UTC').dt.tz_convert(ist)
    devices_df['last_seen'] = devices_df['last_seen'].dt.strftime('%Y-%m-%d %H:%M:%S IST')

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
    uptime_val = health_df.iloc[-1].get('uptime', '0h 0m') if not health_df.empty else "--"
    m1.metric("Uptime", f"⏱️ {uptime_val}")
    
    if op_mode == "Mode A: Global Watchtower":
        m2.metric("Cloud IP", f"🌐 {AWS_IP}")
    else:
        gw_val = health_df.iloc[-1].get('gateway_ip', 'Detecting...') if not health_df.empty else "--"
        m2.metric("Pi Gateway", f"🌐 {gw_val}")

st.divider()

# --- HELPER: DISPLAY SECTION ---
def display_attack_section(df, attack_key):
    if not df.empty:
        st.dataframe(df, use_container_width=True, hide_index=True)
        if attack_key in PLAYBOOK:
            st.markdown(f'<div class="playbook-card"><strong></strong> {PLAYBOOK[attack_key]["solution"]}</div>', unsafe_allow_html=True)
    else:
        st.info(f"✅ System clear for {attack_key}.")

# --- MODE A: GLOBAL WATCHTOWER ---
if op_mode == "Mode A: Global Watchtower":
    st.markdown("### 🌐 Global Threat Intelligence & Research")
    col_map, col_hist = st.columns([1.2, 1])

    with col_map:
        st.markdown("#### Real-Time Attack Heatmap")
        if not events_df.empty and 'latitude' in events_df.columns and not events_df['latitude'].isnull().all():
            st.map(events_df.dropna(subset=['latitude', 'longitude']), latitude='latitude', longitude='longitude', color='#ec4899', size=40)
        else:
            st.info("📡 System Ready. Awaiting global telemetry from AWS VPS...")

    with col_hist:
        st.markdown("#### Historical Botnet Archive")
        if not events_df.empty and len(events_df) > 1:
            st.dataframe(events_df.sort_values("timestamp", ascending=False), height=450, use_container_width=True, hide_index=True)
        else:
            st.info("🗄️ Archive currently empty. Fresh logs will appear here.")

    st.divider()

# --- MODE B: LOCAL SENTINEL ---
else:
    st.markdown("### 📱 Local Sentinel & Infection Zone")

    if not health_df.empty and not devices_df.empty:
        gateway_ip = health_df.iloc[-1].get('gateway_ip', '0.0.0.0')
        gateway_prefix = ".".join(gateway_ip.split('.')[:-1])
        
        live_devices = devices_df[devices_df['ip_address'].str.startswith(gateway_prefix)]
        
        if not live_devices.empty:
            col_l, col_r = st.columns([1, 1.2])
            
            with col_l:
                st.markdown("**Discovered Local Assets**")
                selected_ip = st.selectbox("🎯 Select Target Device:", options=live_devices['ip_address'].unique())
                st.dataframe(live_devices, use_container_width=True, hide_index=True)
            
            with col_r:
                st.markdown(f"#### 🔍 Deep Inspection: {selected_ip}")
                
                # --- FIXED: SMART TOGGLE & BROWSING HISTORY BUTTONS ---
                c_block, c_web = st.columns(2)
                
                # Toggle logic based on banned list
                is_banned = False
                if not banned_df.empty and 'Banned IP' in banned_df.columns:
                    is_banned = selected_ip in banned_df['Banned IP'].values

                with c_block:
                    if is_banned:
                        if st.button(f"🔓 Manual Unblock {selected_ip}", type="primary", use_container_width=True):
                            send_command(selected_ip, "UNBLOCK")
                    else:
                        if st.button(f"🚫 Permanent Block {selected_ip}", use_container_width=True):
                            send_command(selected_ip, "BLOCK")
                
                with c_web:
                    show_web = st.button("🌐 View Browsing History", use_container_width=True)

                if show_web:
                    st.info(f"Analyzing DNS telemetry for {selected_ip}...")
                    if not web_df.empty and 'source_ip' in web_df.columns:
                        user_history = web_df[web_df['source_ip'] == selected_ip]
                        if not user_history.empty:
                            st.table(user_history[['timestamp', 'domain']].head(10))
                        else:
                            st.info("No browsing history found for this device.")
                    else:
                        st.warning("Web history log is currently empty.")

                # --- DEEP INSPECTION TAB (Removed Raw Telemetry) ---
                st.divider()
                st.markdown("##### 🔴 Hostile History")
                if not events_df.empty and 'source_ip' in events_df.columns:
                    # FIX: Explicit IP string comparison for filtering
                    ip_events = events_df[events_df['source_ip'].astype(str) == str(selected_ip)]
                    if not ip_events.empty:
                        st.warning(f"Detected {len(ip_events)} malicious signatures.")
                        st.dataframe(ip_events[['timestamp', 'attack_type', 'evidence', 'confidence']], use_container_width=True, hide_index=True)
                    else: 
                        st.success("Clean: No hostile behavior found.")
    else:
        st.info("📡 Scanning Local Network... Connect a device to the Sentry AP to begin.")
    
    st.divider()

# --- LIVE THREAT INTELLIGENCE ---
st.markdown("### 📡 Live Threat Intelligence")
tab1, tab2, tab3, tab4, tab5 = st.tabs(["🎯 Port Scans", "🦠 Malware", "🔑 Brute Force", "🌐 DNS Security", "🚫 Banned List"])

with tab1:
    scan_data = events_df[events_df['attack_type'].str.contains('PortScan|Heartbeat|Connection', na=False)] if not events_df.empty else pd.DataFrame()
    display_attack_section(scan_data, "PortScan")

with tab2:
    mal_data = events_df[events_df['attack_type'].str.contains('Malware', na=False)] if not events_df.empty else pd.DataFrame()
    display_attack_section(mal_data, "Malware")

with tab3:
    brute_data = events_df[events_df['attack_type'].str.contains('Brute|SHARK|SSH', na=False)] if not events_df.empty else pd.DataFrame()
    display_attack_section(brute_data, "Brute Force")

with tab4:
    dns_data = events_df[events_df['attack_type'].str.contains('DNS|Spoof|Query|Poison', na=False)] if not events_df.empty else pd.DataFrame()
    display_attack_section(dns_data, "DNS_Spoof")

with tab5:
    if not banned_df.empty: 
        st.dataframe(banned_df, use_container_width=True, hide_index=True)
    else: 
        st.info("🛡️ No active IP bans in the local kernel.")
