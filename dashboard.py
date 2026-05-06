from github import Github
import streamlit as st
import pandas as pd
from datetime import datetime
import pytz
import sqlite3

DB_PATH = "nexus_security.db"

# --- CONFIG ---
AWS_IP = "51.21.135.152"
RAW_URL = "https://raw.githubusercontent.com/vinayak-salian/honeypot-idps/main/logs/"
ist = pytz.timezone('Asia/Kolkata')

st.set_page_config(page_title="Nexus Security Core", page_icon="🛡️", layout="wide")

# ---------------- FETCH SQL ----------------
@st.cache_data(ttl=5)
def fetch_sql_data(query):
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql(query, conn)
        conn.close()

        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

        return df
    except:
        return pd.DataFrame()

# ---------------- FETCH LOGS ----------------
@st.cache_data(ttl=10)
def fetch_logs(filename):
    try:
        url = f"{RAW_URL}{filename}?t={datetime.now().timestamp()}"
        df = pd.read_csv(url)

        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

        return df
    except:
        return pd.DataFrame()

# ---------------- COMMAND ----------------
def send_command(ip, action):
    try:
        g = Github(st.secrets["GITHUB_TOKEN"])
        repo = g.get_repo("vinayak-salian/honeypot-idps")

        file_path = "logs/action_queue.csv"

        try:
            contents = repo.get_contents(file_path)
            existing_data = contents.decoded_content.decode()
        except:
            existing_data = "timestamp,ip,action\n"
            repo.create_file(file_path, "init", existing_data)
            contents = repo.get_contents(file_path)

        new_line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')},{ip},{action}\n"
        updated = existing_data + new_line

        repo.update_file(contents.path, "C2 action", updated, contents.sha)
        st.success(f"{action} queued for {ip}")

    except Exception as e:
        st.error(f"Command failed: {e}")

# ---------------- LOAD DATA ----------------
health_df = fetch_logs("system_status.csv")
devices_df = fetch_logs("known_devices.csv")
banned_df = fetch_logs("banned_ips.csv")
web_df = fetch_logs("web_history.csv")

global_events_df = fetch_sql_data("""
SELECT * FROM attack_logs ORDER BY timestamp DESC LIMIT 1000
""")

# ---------------- CLEAN DATA ----------------

# 🔥 CLEAN GLOBAL (remove local noise)
if not global_events_df.empty and 'source_ip' in global_events_df.columns:
    global_events_df = global_events_df[
        ~global_events_df['source_ip'].astype(str).str.startswith(("192.168.", "127.", "10.42."))
    ]

# 🔥 LOCAL = only hotspot
local_events_df = fetch_sql_data("""
SELECT * FROM attack_logs WHERE source_ip LIKE '10.42.%'
ORDER BY timestamp DESC LIMIT 500
""")

# 🔥 DEVICES CLEAN
if not devices_df.empty and 'ip_address' in devices_df.columns:
    devices_df = devices_df[
        devices_df['ip_address'].astype(str).str.startswith("10.42.")
    ]

# ---------------- CSS (UNCHANGED) ----------------
st.markdown("""
<style>
.stApp { background-color: #050505; color: #e2e8f0; }
.main-header { font-size: 2.2rem; background: linear-gradient(90deg, #3b82f6, #ec4899); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: 700; margin-bottom: 5px; }
.status-online { color: #10b981; background: rgba(16, 185, 129, 0.1); padding: 5px 15px; border-radius: 20px; border: 1px solid #10b981; font-size: 0.8rem; }
.status-offline { color: #ef4444; background: rgba(239, 68, 68, 0.1); padding: 5px 15px; border-radius: 20px; border: 1px solid #ef4444; font-size: 0.8rem; }
</style>
""", unsafe_allow_html=True)

# ---------------- SIDEBAR ----------------
st.sidebar.title("🎮 Command Center")
mode = st.sidebar.radio("Mode", ["Global", "Local"])

# ---------------- HEADER ----------------
c1, c2 = st.columns([2,1])

with c1:
    st.markdown('<div class="main-header">Nexus Security Core</div>', unsafe_allow_html=True)

    is_online = False
    last_sync_str = "No heartbeat"

    if not health_df.empty:
        try:
            last = health_df.iloc[-1]
            ts = pd.to_datetime(last['timestamp'], errors='coerce')

            if pd.notnull(ts):
                diff = (datetime.now() - ts).total_seconds()
                if diff < 900:
                    is_online = True

                last_sync_str = ts.strftime("%H:%M:%S")

        except:
            pass

    cls = "status-online" if is_online else "status-offline"
    txt = f"🟢 PI ONLINE | Pulse: {last_sync_str}" if is_online else f"🔴 PI OFFLINE | Pulse: {last_sync_str}"

    st.markdown(f'<span class="{cls}">{txt}</span>', unsafe_allow_html=True)

with c2:
    m1, m2 = st.columns(2)

    uptime = "--"
    gateway = "--"

    if not health_df.empty:
        uptime = health_df.iloc[-1].get("uptime", "--")
        gateway = health_df.iloc[-1].get("gateway_ip", "--")

    m1.metric("Uptime", f"⏱️ {uptime}")

    if mode == "Global":
        m2.metric("Cloud", AWS_IP)
    else:
        m2.metric("Gateway", gateway)

st.divider()

# ---------------- GLOBAL ----------------
if mode == "Global":
    st.subheader("🌍 Global Threat Intelligence")

    if not global_events_df.empty:
        st.dataframe(global_events_df)

        st.markdown("### 🗺️ Attack Map")

        if 'latitude' in global_events_df.columns:
            st.map(global_events_df.dropna(subset=['latitude','longitude']))
        else:
            st.info("No geo data")

    else:
        st.info("No global data")

# ---------------- LOCAL ----------------
else:
    st.subheader("🏠 Local Network Defense")

    if not devices_df.empty:
        st.dataframe(devices_df)
    else:
        st.warning("No local devices")

    if not local_events_df.empty:
        ips = local_events_df['source_ip'].unique()
        selected_ip = st.selectbox("Select IP", ips)

        c1, c2 = st.columns(2)

        if c1.button("🚫 Block"):
            send_command(selected_ip, "BLOCK")

        if c2.button("🔓 Unblock"):
            send_command(selected_ip, "UNBLOCK")

        st.dataframe(local_events_df[local_events_df['source_ip'] == selected_ip])

    else:
        st.info("No local threats")

st.divider()

# ---------------- THREATS ----------------
st.markdown("### 📊 Threat Categories")

active_df = global_events_df if mode == "Global" else local_events_df

def filt(key):
    return active_df[active_df['attack_type'].str.contains(key, na=False)] if not active_df.empty else pd.DataFrame()

tabs = st.tabs(["🎯 Scan", "🦠 Malware", "🔑 Brute", "🌐 DNS"])

with tabs[0]:
    st.dataframe(filt("Scan"))

with tabs[1]:
    st.dataframe(filt("Malware"))

with tabs[2]:
    st.dataframe(filt("Brute"))

with tabs[3]:
    st.dataframe(filt("DNS"))
