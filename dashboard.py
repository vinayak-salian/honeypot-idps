import streamlit as st
import pandas as pd
import requests
import sqlite3

# --- CONFIG ---
API_BASE = "https://roots-sentence-options-medication.trycloudflare.com"
DB_PATH = "/home/vinayak/honeypot_project/nexus_security.db"

st.set_page_config(page_title="Nexus Security Core", layout="wide")

# --- EMOJI FIX ---
st.markdown("""
<style>
body {
    font-family: "Segoe UI Emoji", "Noto Color Emoji", sans-serif;
}
</style>
""", unsafe_allow_html=True)

# --- FETCH EVENTS ---
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

# --- FETCH DEVICES ---
@st.cache_data(ttl=5)
def fetch_devices():
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql("SELECT * FROM known_devices", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

# --- GEO LOCATION ---
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
st.sidebar.title("Command Center")
mode = st.sidebar.radio("Mode", ["Global", "Local"])

# --- HEADER ---
st.title("Nexus Security Core")

# --- STATS ---
col1, col2, col3 = st.columns(3)
col1.metric("Total Events", len(events_df))
col2.metric("Global", len(global_df))
col3.metric("Local", len(local_df))

# ======================
# 🌍 GLOBAL MODE
# ======================
if mode == "Global":
    st.subheader("Global Threat Intelligence")

    if not global_df.empty:
        st.dataframe(global_df.sort_values("timestamp", ascending=False))

        # 🔥 MAP
        st.markdown("### Attack Map")

        map_df = build_map(global_df)

        if not map_df.empty:
            st.map(map_df)
        else:
            st.info("No geolocation data")

    else:
        st.info("No global attacks")

# ======================
# 🏠 LOCAL MODE
# ======================
else:
    st.subheader("Local Network Defense")

    # DEVICE PANEL
    st.markdown("### Devices")

    if not devices_df.empty:
        st.dataframe(devices_df)
    else:
        st.info("No devices detected")

    # CONTROL
    if not local_df.empty:
        ip_list = local_df['source_ip'].dropna().unique()
        selected_ip = st.selectbox("Select IP", ip_list)

        col1, col2 = st.columns(2)

        if col1.button("Block"):
            send_command(selected_ip, "block")

        if col2.button("Unblock"):
            send_command(selected_ip, "unblock")

        st.markdown("### Attack History")

        st.dataframe(local_df[local_df['source_ip'] == selected_ip])

    else:
        st.info("No local threats")

# ======================
# 📊 BREAKDOWN
# ======================
st.markdown("### Threat Categories")

def safe(df, key):
    return df[df['attack_type'].str.contains(key, na=False)] if not df.empty else pd.DataFrame()

tabs = st.tabs(["Scan", "Malware", "Brute", "DNS"])

with tabs[0]:
    st.dataframe(safe(events_df, "Scan"))

with tabs[1]:
    st.dataframe(safe(events_df, "Malware"))

with tabs[2]:
    st.dataframe(safe(events_df, "Brute"))

with tabs[3]:
    st.dataframe(safe(events_df, "DNS"))
