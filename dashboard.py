import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import pytz

# --- 1. CONFIGURATION ---
RAW_URL = "https://raw.githubusercontent.com/vinayak-salian/honeypot-idps/main/logs/"
ist = pytz.timezone('Asia/Kolkata')

st.set_page_config(page_title="Nexus Security Core", page_icon="🛡️", layout="wide")

# --- 2. LOG FETCHING ---
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

# Data Acquisition
health_df = fetch_logs("system_status.csv")
events_df = fetch_logs("security_events.csv")
devices_df = fetch_logs("known_devices.csv")
traffic_df = fetch_logs("traffic_metrics.csv")
banned_df = fetch_logs("banned_ips.csv")

# --- 3. SIDEBAR MODE SELECTOR ---
st.sidebar.title("🎮 Command & Control")
mode = st.sidebar.radio(
    "Select Operational Mode:",
    ["Mode A: Global Watchtower", "Mode B: Local Sentinel"]
)

# --- 4. HEADER & UPTIME (Always Visible) ---
c_h1, c_h2 = st.columns([2, 1])
with c_h1:
    st.markdown(f'<div class="main-header">Nexus Security Core: {mode.split(":")[1]}</div>', unsafe_allow_html=True)
    # [Heartbeat logic remains the same...]
    # (Simplified for brevity, keep your existing pulse code here)

with c_h2:
    if not health_df.empty:
        st.metric("System Uptime", health_df.iloc[-1]['uptime'])

st.divider()

# --- 5. MODE A: GLOBAL WATCHTOWER ---
if mode == "Mode A: Global Watchtower":
    st.markdown("### 🌐 Global Threat Intelligence")
    col_map, col_hist = st.columns([1.2, 1])

    with col_map:
        st.markdown("#### Real-Time Attack Heatmap")
        if not events_df.empty and 'latitude' in events_df.columns:
            st.map(events_df.dropna(subset=['latitude', 'longitude']), color='#ec4899')
        else:
            st.info("Awaiting global coordinates...")

    with col_hist:
        st.markdown("#### Historical Botnet Archive")
        if not events_df.empty:
            st.dataframe(events_df.sort_values("timestamp", ascending=False), height=400, use_container_width=True)

# --- 6. MODE B: LOCAL SENTINEL (Infection Zone) ---
else:
    st.markdown("### 📱 Local Network Census & Live Infection Zone")
    if not devices_df.empty:
        col_l, col_r = st.columns([1, 1.2])
        with col_l:
            st.markdown("**Discovered Assets (Wi-Fi + LAN)**")
            selected_ip = st.selectbox("🎯 Target Inspection:", options=devices_df['ip_address'].unique())
            st.dataframe(devices_df, use_container_width=True)
        
        with col_r:
            st.markdown(f"#### 🔍 Live Traffic: {selected_ip}")
            t1, t2 = st.tabs(["🔴 Hostile History", "📊 Live Packet Stream"])
            # [Your existing tabs code here...]
    else:
        st.info("No devices detected on Rogue AP or LAN.")

# --- 7. SHARED MITIGATION (Keep your Playbook and CSS here) ---
