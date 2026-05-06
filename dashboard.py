import streamlit as st
import pandas as pd
import requests
import sqlite3
from datetime import datetime

# --- CONFIG ---
API_BASE = "https://roots-sentence-options-medication.trycloudflare.com"
DB_PATH = "/home/vinayak/honeypot_project/nexus_security.db"

st.set_page_config(page_title="Nexus Security Core", layout="wide")

# --- EMOJI FIX (SAFE) ---
st.markdown("""
<style>
body {
    font-family: "Segoe UI Emoji","Noto Color Emoji","Apple Color Emoji",sans-serif;
}
</style>
""", unsafe_allow_html=True)

# ---------------- FETCH EVENTS ----------------
@st.cache_data(ttl=5)
def fetch_events():
    try:
        res = requests.get(f"{API_BASE}/get_logs", timeout=5)
        data = res.json()

        if not isinstance(data, list):
            return pd.DataFrame(columns=["timestamp","source_ip","attack_type","confidence","evidence","env"])

        df = pd.DataFrame(data)

        for col in ["timestamp","source_ip","attack_type","confidence","evidence","env"]:
            if col not in df.columns:
                df[col] = "global" if col == "env" else None

        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

        return df

    except Exception as e:
        st.warning(f"⚠️ API Offline: {e}")
        return pd.DataFrame(columns=["timestamp","source_ip","attack_type","confidence","evidence","env"])

# ---------------- FETCH DEVICES ----------------
@st.cache_data(ttl=5)
def fetch_devices():
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql("SELECT * FROM known_devices", conn)
        conn.close()

        if df.empty:
            return df

        # 🔥 FIX: ONLY hotspot devices
        df = df[df['ip_address'].str.startswith("10.42.")]

        # 🔥 FIX: only online devices
        if "status" in df.columns:
            df = df[df['status'] == "online"]

        return df

    except:
        return pd.DataFrame()

# ---------------- FETCH HEARTBEAT ----------------
@st.cache_data(ttl=5)
def fetch_health():
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql("SELECT * FROM system_status ORDER BY timestamp DESC LIMIT 1", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

# ---------------- GEO ----------------
@st.cache_data(ttl=300)
def get_geo(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=lat,lon", timeout=3).json()
        return r.get("lat"), r.get("lon")
    except:
        return None, None

def build_map(df):
    coords = []
    for ip in df['source_ip'].dropna().unique():
        lat, lon = get_geo(ip)
        if lat and lon:
            coords.append({"lat": lat, "lon": lon})
    return pd.DataFrame(coords)

# ---------------- MITIGATION ----------------
def send_command(ip, action):
    try:
        requests.post(f"{API_BASE}/{action.lower()}", json={"ip": ip})
        st.success(f"{action} executed for {ip}")
    except:
        st.error("Command failed")

# ---------------- LOAD ----------------
events_df = fetch_events()
devices_df = fetch_devices()
health_df = fetch_health()

# 🔥 FIX: Proper separation
global_df = events_df[events_df['env'] == 'global'] if not events_df.empty else pd.DataFrame()
local_df = events_df[events_df['env'] == 'local'] if not events_df.empty else pd.DataFrame()

# ---------------- SIDEBAR ----------------
st.sidebar.title("🎮 Command Center")
mode = st.sidebar.radio("Mode", ["Global", "Local"])

# ---------------- HEADER ----------------
st.title("🛡️ Nexus Security Core")

# ---------------- HEARTBEAT ----------------
if not health_df.empty:
    last = health_df.iloc[0]
    last_time = pd.to_datetime(last.get("timestamp"))
    uptime = last.get("uptime", "--")

    is_online = (datetime.now() - last_time).seconds < 120

    if is_online:
        st.success(f"🟢 PI ONLINE | ⏱️ Uptime: {uptime}")
    else:
        st.error(f"🔴 PI OFFLINE | Last Seen: {last_time}")

# ---------------- STATS ----------------
col1, col2, col3 = st.columns(3)
col1.metric("Total Events", len(events_df))
col2.metric("Global", len(global_df))
col3.metric("Local", len(local_df))

# ================= GLOBAL =================
if mode == "Global":
    st.subheader("🌍 Global Threat Intelligence")

    active_df = global_df

    if not active_df.empty:
        st.dataframe(active_df.sort_values("timestamp", ascending=False))

        st.markdown("### 🗺️ Attack Map")
        map_df = build_map(active_df)

        if not map_df.empty:
            st.map(map_df)
        else:
            st.info("No geo data")

    else:
        st.info("No global attacks")

# ================= LOCAL =================
else:
    st.subheader("🏠 Local Network Defense")

    st.markdown("### 📡 Devices")

    if not devices_df.empty:
        st.dataframe(devices_df)
    else:
        st.warning("No active local devices")

    active_df = local_df

    if not active_df.empty:
        ip_list = active_df['source_ip'].dropna().unique()
        selected_ip = st.selectbox("🎯 Select IP", ip_list)

        col1, col2 = st.columns(2)

        if col1.button("🚫 Block"):
            send_command(selected_ip, "block")

        if col2.button("🔓 Unblock"):
            send_command(selected_ip, "unblock")

        st.markdown("### 📜 Attack History")
        st.dataframe(active_df[active_df['source_ip'] == selected_ip])

    else:
        st.info("No local threats")

# ================= THREAT TABS =================
st.markdown("### 📊 Threat Categories")

def safe(df, key):
    return df[df['attack_type'].str.contains(key, na=False)] if not df.empty else pd.DataFrame()

# 🔥 FIX: use correct dataset per mode
active_df = global_df if mode == "Global" else local_df

tabs = st.tabs(["🎯 Scan", "🦠 Malware", "🔑 Brute", "🌐 DNS"])

with tabs[0]:
    st.dataframe(safe(active_df, "Scan"))

with tabs[1]:
    st.dataframe(safe(active_df, "Malware"))

with tabs[2]:
    st.dataframe(safe(active_df, "Brute"))

with tabs[3]:
    st.dataframe(safe(active_df, "DNS"))
