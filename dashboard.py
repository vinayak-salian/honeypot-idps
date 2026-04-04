import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import pytz
import os
from github import Github

# --- CONFIGURATION ---
RAW_URL = "https://raw.githubusercontent.com/vinayak-salian/honeypot-idps/main/logs/"

st.set_page_config(
    page_title="Nexus Security Core",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- CUSTOM CSS (Cyberpunk Theme) ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500&display=swap');

    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
    .stApp { background-color: #050505; background-image: radial-gradient(circle at 50% 0%, #171124 0%, #050505 50%); color: #e2e8f0; }
    .main-header { font-size: 2.5rem; background: linear-gradient(90deg, #3b82f6, #8b5cf6, #ec4899); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: 700; }
    .status-badge { display: inline-block; padding: 0.35rem 1rem; border-radius: 50px; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.2); color: #10b981; font-size: 0.875rem; margin-top: 1rem; }
    
    .cyber-card { background: rgba(15, 23, 42, 0.5); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 8px; padding: 1.25rem; backdrop-filter: blur(10px); margin-bottom: 1rem;}
    .card-title { font-size: 0.75rem; color: #cbd5e1; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
    .card-value { font-size: 1.8rem; font-weight: 700; color: #f8fafc; font-family: 'Fira Code', monospace; }
    
    .dataframe-container { border-radius: 12px; overflow: auto; max-height: 400px; border: 1px solid rgba(255, 255, 255, 0.05); background: rgba(15, 23, 42, 0.4); }
    table { width: 100%; border-collapse: collapse; font-family: 'Fira Code', monospace; font-size: 0.85rem; }
    th { text-align: left; padding: 12px; background: rgba(30, 41, 59, 0.8); color: #f8fafc; position: sticky; top: 0; }
    td { padding: 10px; border-bottom: 1px solid rgba(255, 255, 255, 0.02); }
</style>
""", unsafe_allow_html=True)

ist = pytz.timezone('Asia/Kolkata')

# --- DATA FETCHING ---
@st.cache_data(ttl=15)
def fetch_logs(filename):
    try:
        return pd.read_csv(RAW_URL + filename)
    except:
        return pd.DataFrame()

# Fetch All Master Data
events_df = fetch_logs("security_events.csv")
banned_df = fetch_logs("banned_ips.csv")
traffic_df = fetch_logs("traffic_metrics.csv")
devices_df = fetch_logs("known_devices.csv") # The Network Census

# --- HEADER ---
col_h1, col_h2 = st.columns([1, 1])
with col_h1:
    st.markdown('<div class="main-header">Nexus Security Core</div>', unsafe_allow_html=True)
    st.markdown('<div class="status-badge">🟢 C2 CLOUD DASHBOARD • ONLINE</div>', unsafe_allow_html=True)
with col_h2:
    st.markdown(f"<div style='text-align: right; color: #94a3b8; font-family: \"Fira Code\"; pt-4'>SYS_TIME // {datetime.now(ist).strftime('%H:%M:%S')}</div>", unsafe_allow_html=True)

# --- SECTION 1: NETWORK CENSUS (Connected Devices) ---
st.markdown("### 📱 Network Census")
st.markdown("<p style='color: #94a3b8;'>Internal devices discovered by Sentry. Use the C2 panel below to block unauthorized hardware.</p>", unsafe_allow_html=True)

if not devices_df.empty:
    cols = st.columns(len(devices_df) if len(devices_df) < 5 else 4)
    for i, row in devices_df.iterrows():
        with cols[i % 4]:
            trusted_color = "#10b981" if row.get('is_trusted') == 1 else "#ef4444"
            st.markdown(f"""
            <div class="cyber-card">
                <div class="card-title">Device IP: {row['ip_address']}</div>
                <div style="color: {trusted_color}; font-size: 0.8rem; font-weight: bold;">
                    {'TRUSTED' if row.get('is_trusted') == 1 else 'UNTRUSTED'}
                </div>
                <div style="font-size: 0.7rem; color: #64748b; font-family: 'Fira Code';">MAC: {row['mac_address']}</div>
            </div>
            """, unsafe_allow_html=True)
else:
    st.info("No network census data available. Ensure your Pi is scanning the local network.")

# --- SECTION 2: LIVE TRAFFIC & HEATMAP ---
col_m1, col_m2 = st.columns([2, 1])

with col_m1:
    st.markdown("### 🌍 Global Threat Heatmap")
    if not events_df.empty and 'latitude' in events_df.columns:
        map_data = events_df.dropna(subset=['latitude', 'longitude'])
        st.map(map_data, latitude='latitude', longitude='longitude', color='#ec4899', size=40)
    else:
        st.warning("Awaiting geospatial data...")

with col_traffic := col_m2:
    st.markdown("### 📊 Network Heartbeat")
    if not traffic_df.empty:
        latest = traffic_df.iloc[0]
        st.markdown(f"""
        <div class="cyber-card">
            <div class="card-title">Bandwidth Usage</div>
            <div class="card-value">{latest.get('total_bytes', 0)} B</div>
            <hr style="opacity: 0.1">
            <div style="display: flex; justify-content: space-between; font-size: 0.8rem;">
                <span>TCP: {latest.get('tcp_count', 0)}</span>
                <span>UDP: {latest.get('udp_count', 0)}</span>
                <span>ICMP: {latest.get('icmp_count', 0)}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.info("Awaiting traffic telemetry...")

# --- SECTION 3: MITIGATION & BLOCKING ---
st.markdown("### 🛡️ Command & Control (C2)")
c1, c2 = st.columns([1, 2])

with c1:
    st.markdown("#### ⚡ Manual Override")
    with st.form("c2_form", clear_on_submit=True):
        ip_to_block = st.text_input("Target IP:", placeholder="192.168.x.x")
        reason = st.selectbox("Reason", ["Unauthorized Device", "Brute Force", "Port Scan", "Malware"])
        if st.form_submit_button("QUEUE BLOCK COMMAND"):
            if ip_to_block:
                try:
                    g = Github(st.secrets["GITHUB_TOKEN"])
                    repo = g.get_repo("vinayak-salian/honeypot-idps")
                    cmd = f"{ip_to_block},{reason},{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    try:
                        contents = repo.get_contents("logs/block_queue.txt")
                        repo.update_file(contents.path, f"C2: Block {ip_to_block}", contents.decoded_content.decode() + "\n" + cmd, contents.sha)
                    except:
                        repo.create_file("logs/block_queue.txt", "C2: Init Queue", cmd)
                    st.success(f"Command Sent: Blocking {ip_to_block}")
                except Exception as e:
                    st.error(f"C2 Error: {e}")

with c2:
    st.markdown("#### 🚫 Active Containment (Banned IPs)")
    if not banned_df.empty:
        st.markdown(f'<div class="dataframe-container">{banned_df.to_html(index=False, classes="custom-table")}</div>', unsafe_allow_html=True)
    else:
        st.success("Containment zone empty.")

# --- SECTION 4: HISTORICAL INTELLIGENCE ---
st.markdown("### 📜 Master Security Logs (Historical)")
if not events_df.empty:
    st.markdown(f'<div class="dataframe-container">{events_df.sort_values("timestamp", ascending=False).to_html(index=False, classes="custom-table")}</div>', unsafe_allow_html=True)
else:
    st.info("No historical events recorded yet.")

st.markdown("<div style='text-align: center; color: #475569; padding-top: 50px;'>Nexus System Build v2.0.5 • Remote C2 Encrypted</div>", unsafe_allow_html=True)
