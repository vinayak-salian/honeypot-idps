import streamlit as st
import pandas as pd
import requests
import sqlite3

# --- CONFIG ---
API_BASE = "https://affect-respective-discussed-realtor.trycloudflare.com"
DB_PATH = "/home/vinayak/honeypot_project/nexus_security.db"

st.set_page_config(page_title="Nexus Security Core", page_icon="???", layout="wide")

# --- FETCH ATTACK DATA ---
@st.cache_data(ttl=5)
def fetch_events():
    try:
        res = requests.get(f"{API_BASE}/get_logs", timeout=5)
        df = pd.DataFrame(res.json())

        if df.empty:
            return df

        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

        # ?? Separate env
        if 'env' not in df.columns:
            df['env'] = 'global'

        return df

    except:
        return pd.DataFrame()

# --- FETCH DEVICES (CENSUS) ---
@st.cache_data(ttl=5)
def fetch_devices():
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM known_devices", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

# --- MITIGATION ---
def send_command(ip, action):
    try:
        requests.post(f"{API_BASE}/{action.lower()}", json={"ip": ip})
        st.success(f"{action} executed for {ip}")
    except:
        st.error("Command failed")

# --- LOAD DATA ---
events_df = fetch_events()
devices_df = fetch_devices()

if not events_df.empty and 'env' in events_df.columns:
    global_df = events_df[events_df['env'] == 'global']
    local_df = events_df[events_df['env'] == 'local']
else:
    global_df = pd.DataFrame()
    local_df = pd.DataFrame()

# --- SIDEBAR ---
st.sidebar.title("?? Command Center")
mode = st.sidebar.radio("Mode", ["Global", "Local"])

# --- HEADER ---
st.title("??? Nexus Security Core")

# --- STATS ---
col1, col2, col3 = st.columns(3)

col1.metric("Total Events", len(events_df))
col2.metric("Global Attacks", len(global_df))
col3.metric("Local Attacks", len(local_df))

# =========================
# ?? GLOBAL MODE
# =========================
if mode == "Global":
    st.subheader("?? Global Threat Intelligence")

    if not global_df.empty:
        st.dataframe(global_df.sort_values("timestamp", ascending=False), use_container_width=True)
    else:
        st.info("No global attacks yet")

# =========================
# ?? LOCAL MODE
# =========================
else:
    st.subheader("?? Local Network Defense")

    # -------- DEVICE PANEL --------
    st.markdown("### ?? Devices (Live)")

    if not devices_df.empty:
        st.dataframe(devices_df, use_container_width=True)
    else:
        st.info("No devices detected")

    # -------- ATTACK CONTROL --------
    st.markdown("### ?? Threat Control")

    if not local_df.empty:
        ips = local_df['source_ip'].dropna().unique()

        selected_ip = st.selectbox("Select Suspicious IP", ips)

        col1, col2 = st.columns(2)

        with col1:
            if st.button("?? Block"):
                send_command(selected_ip, "block")

        with col2:
            if st.button("?? Unblock"):
                send_command(selected_ip, "unblock")

        st.markdown("### ?? Attack History")

        ip_events = local_df[local_df['source_ip'] == selected_ip]

        st.dataframe(
            ip_events[['timestamp', 'attack_type', 'confidence', 'evidence']],
            use_container_width=True
        )
    else:
        st.info("No local threats detected")

# =========================
# ?? ATTACK BREAKDOWN
# =========================
st.markdown("### ?? Threat Breakdown")

def safe_filter(df, keyword):
    return df[df['attack_type'].str.contains(keyword, na=False)] if not df.empty else pd.DataFrame()

tabs = st.tabs(["PortScan", "Malware", "Brute Force", "DNS"])

with tabs[0]:
    st.dataframe(safe_filter(events_df, "Scan"))

with tabs[1]:
    st.dataframe(safe_filter(events_df, "Malware"))

with tabs[2]:
    st.dataframe(safe_filter(events_df, "Brute"))

with tabs[3]:
    st.dataframe(safe_filter(events_df, "DNS"))
