import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime
import pytz
import requests

# --- CONFIG ---
API_BASE = "https://affect-respective-discussed-realtor.trycloudflare.com"  
ist = pytz.timezone('Asia/Kolkata')

st.set_page_config(page_title="Nexus Security Core", page_icon="🛡️", layout="wide")

# --- FETCH DATA FROM API ---
@st.cache_data(ttl=5)
def fetch_events():
    try:
        res = requests.get(f"{API_BASE}/get_logs", timeout=5)
        data = res.json()

        if not isinstance(data, list):
            return pd.DataFrame()

        df = pd.DataFrame(data)

        # Ensure required columns exist
        required_cols = ["timestamp", "source_ip", "attack_type", "confidence", "evidence"]
        for col in required_cols:
            if col not in df.columns:
                df[col] = None

        # Convert timestamp
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

        return df

    except Exception as e:
        st.error(f"Fetch error: {e}")
        return pd.DataFrame(columns=["timestamp", "source_ip", "attack_type", "confidence", "evidence"])

# --- MITIGATION API ---
def send_command(ip, action):
    try:
        requests.post(f"{API_BASE}/{action.lower()}", json={"ip": ip})
        st.success(f"{action} executed for {ip}")
    except Exception as e:
        st.error(f"Command failed: {e}")

# --- DATA ---
events_df = fetch_events()

global_events_df = events_df.copy()
local_events_df = events_df.copy()

# --- SAFE FILTER FUNCTION ---
def safe_filter(df, keyword):
    if df.empty or 'attack_type' not in df.columns:
        return pd.DataFrame()
    return df[df['attack_type'].str.contains(keyword, na=False)]

# --- PLAYBOOK ---
PLAYBOOK = {
    "PortScan": {"solution": "Block IP, enable rate-limiting"},
    "Malware": {"solution": "Isolate system, scan files"},
    "Brute Force": {"solution": "Enable SSH keys, Fail2Ban"},
    "DNS": {"solution": "Flush DNS, enable DNSSEC"}
}

# --- CSS (UNCHANGED) ---
st.markdown("""<style>
.stApp { background-color: #050505; color: #e2e8f0; }
.main-header { font-size: 2.2rem; background: linear-gradient(90deg, #3b82f6, #ec4899); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: 700; margin-bottom: 5px; }
.status-online { color: #10b981; background: rgba(16, 185, 129, 0.1); padding: 5px 15px; border-radius: 20px; border: 1px solid #10b981; font-size: 0.8rem; }
.status-offline { color: #ef4444; background: rgba(239, 68, 68, 0.1); padding: 5px 15px; border-radius: 20px; border: 1px solid #ef4444; font-size: 0.8rem; }
.playbook-card { background: rgba(59, 130, 246, 0.1); border-left: 5px solid #3b82f6; padding: 15px; border-radius: 5px; margin-bottom: 10px; font-size: 0.9rem; }
</style>""", unsafe_allow_html=True)

# --- MODE ---
st.sidebar.title("🎮 Command Center")
op_mode = st.sidebar.radio("Mode:", ["Global", "Local"])

# --- HEADER ---
st.markdown('<div class="main-header">Nexus Security Core</div>', unsafe_allow_html=True)

# --- GLOBAL MODE ---
if op_mode == "Global":
    st.markdown("### 🌐 Global Threat Intelligence")

    if not global_events_df.empty:
        st.dataframe(global_events_df.sort_values("timestamp", ascending=False), use_container_width=True)
    else:
        st.info("No attacks yet")

# --- LOCAL MODE ---
else:
    st.markdown("### 📱 Local Sentinel")

    if not local_events_df.empty and 'source_ip' in local_events_df.columns:

        selected_ip = st.selectbox("Select IP", local_events_df['source_ip'].dropna().unique())

        col1, col2 = st.columns(2)

        with col1:
            if st.button("🚫 Block"):
                send_command(selected_ip, "block")

        with col2:
            if st.button("🔓 Unblock"):
                send_command(selected_ip, "unblock")

        ip_events = local_events_df[local_events_df['source_ip'] == selected_ip]

        st.dataframe(ip_events[['timestamp', 'attack_type', 'confidence', 'evidence']])

    else:
        st.info("No local data available")

# --- TABS ---
st.markdown("### 📡 Threat Categories")

tabs = st.tabs(["PortScan", "Malware", "Brute Force", "DNS"])

with tabs[0]:
    df = safe_filter(events_df, "Scan")
    st.dataframe(df if not df.empty else pd.DataFrame())

with tabs[1]:
    df = safe_filter(events_df, "Malware")
    st.dataframe(df if not df.empty else pd.DataFrame())

with tabs[2]:
    df = safe_filter(events_df, "Brute")
    st.dataframe(df if not df.empty else pd.DataFrame())

with tabs[3]:
    df = safe_filter(events_df, "DNS")
    st.dataframe(df if not df.empty else pd.DataFrame())
