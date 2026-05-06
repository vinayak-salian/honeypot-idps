import streamlit as st
import pandas as pd
import requests
from datetime import datetime
import pytz

# ---------------- CONFIG ----------------
API_BASE = "https://roots-sentence-options-medication.trycloudflare.com"
ist = pytz.timezone('Asia/Kolkata')

st.set_page_config(page_title="Nexus Security Core", layout="wide")

# ---------------- AUTO REFRESH ----------------
st.experimental_rerun if False else None  # placeholder


# ---------------- GEO HELPERS ----------------
@st.cache_data(ttl=3600)
def get_country(ip):
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country",
            timeout=3
        ).json()
        if r.get("status") == "success":
            return r.get("country")
    except:
        pass
    return None
# ---------------- FETCH EVENTS ----------------
@st.cache_data(ttl=3)
def fetch_events():
    try:
        res = requests.get(f"{API_BASE}/get_logs", timeout=5)
        data = res.json()

        df = pd.DataFrame(data)

        for col in ["timestamp","source_ip","attack_type","confidence","evidence","env"]:
            if col not in df.columns:
                df[col] = "global" if col == "env" else None

        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

        return df

    except:
        return pd.DataFrame(columns=["timestamp","source_ip","attack_type","confidence","evidence","env"])

# ---------------- CLEAN DATA ----------------
def clean_data(df):
    if df.empty:
        return df

    # remove unwanted noise
    df = df[~df['source_ip'].astype(str).str.startswith(("127.","169.254."))]

    return df

# ---------------- RISK SCORE ----------------
def risk_level(conf):
    if conf >= 0.85:
        return "🔴 HIGH"
    elif conf >= 0.6:
        return "🟠 MEDIUM"
    else:
        return "🟢 LOW"

# ---------------- LOAD ----------------
events_df = clean_data(fetch_events())

global_df = events_df[events_df['env'] == 'global']
local_df = events_df[events_df['env'] == 'local']

# ---------------- SIDEBAR ----------------
st.sidebar.title("🎮 Command Center")
mode = st.sidebar.radio("Mode", ["Global", "Local"])

# ---------------- HEADER ----------------
st.title("🛡️ Nexus Security Core")

# ---------------- HEARTBEAT (LOGIC BASED) ----------------
last_seen = events_df['timestamp'].max() if not events_df.empty else None

if last_seen:
    diff = (datetime.now() - last_seen).total_seconds()
    if diff < 120:
        st.success(f"🟢 PI ONLINE | Last Activity: {last_seen.strftime('%H:%M:%S')}")
    else:
        st.error(f"🔴 PI OFFLINE | Last Seen: {last_seen.strftime('%H:%M:%S')}")
else:
    st.warning("⚠️ No heartbeat data")

# ---------------- STATS ----------------
c1,c2,c3 = st.columns(3)
c1.metric("Total Events", len(events_df))
c2.metric("Global", len(global_df))
c3.metric("Local", len(local_df))

# ---------------- GLOBAL ----------------
if mode == "Global":
    st.subheader("🌍 Global Threat Intelligence")

    active_df = global_df

    if not active_df.empty:
        st.dataframe(active_df.sort_values("timestamp", ascending=False))

        st.markdown("### 🗺️ Attack Map")

        geo_df = []

        for ip in active_df['source_ip'].dropna().unique():
            try:
                r = requests.get(f"http://ip-api.com/json/{ip}?fields=lat,lon", timeout=2).json()
                if r.get("lat"):
                    geo_df.append({"lat": r["lat"], "lon": r["lon"]})
            except:
                pass

        if geo_df:
            st.map(pd.DataFrame(geo_df))
        else:
            st.info("No geo data")

    else:
        st.info("No global attacks")

selected_ip = None

# ---------------- LOCAL ----------------
if mode == "Local":
    st.subheader("🏠 Local Network Defense")

    active_df = local_df   # 🔥 DEFINE IT HERE

    if not active_df.empty:
        ip_list = active_df['source_ip'].unique()
        selected_ip = st.selectbox("🎯 Select IP", ip_list)

        # --- SESSION STATE INIT ---
        if "blocked_ips" not in st.session_state:
            st.session_state.blocked_ips = set()

        c1, c2 = st.columns(2)

        is_blocked = selected_ip in st.session_state.blocked_ips

        if not is_blocked:
            if c1.button("🚫 Block"):
                requests.post(f"{API_BASE}/block", json={"ip": selected_ip})
                st.session_state.blocked_ips.add(selected_ip)
                st.rerun()
        else:
            if c2.button("🔓 Unblock"):
                requests.post(f"{API_BASE}/unblock", json={"ip": selected_ip})
                st.session_state.blocked_ips.remove(selected_ip)
                st.rerun()

        st.dataframe(active_df[active_df['source_ip']==selected_ip])

    else:
        st.info("No local threats")
# ---------------- THREAT TABS ----------------
st.markdown("### 📊 Threat Categories")

active_df = global_df if mode == "Global" else local_df

tabs = st.tabs(["🎯 Scan","🦠 Malware","🔑 Brute","🌐 DNS"])

def filt(key):
    return active_df[active_df['attack_type'].str.contains(key, na=False)]

with tabs[0]:
    st.dataframe(filt("Scan"))

with tabs[1]:
    st.dataframe(filt("Malware"))

with tabs[2]:
    st.dataframe(filt("Brute"))

with tabs[3]:
    st.dataframe(filt("DNS"))

# ---------------- LEADERBOARD 🔥 ----------------
st.markdown("### 🏆 Top Attackers")

active_df = global_df if mode == "Global" else local_df

if not active_df.empty:
    leaderboard = (
        active_df.groupby("source_ip")
        .agg(
            attacks=("source_ip", "count"),
            last_seen=("timestamp", "max"),
            max_risk=("confidence", "max")
        )
        .reset_index()
        .sort_values("attacks", ascending=False)
        .head(10)
    )

    # 🔥 Add country ONLY for global
    if mode == "Global":
        leaderboard["country"] = leaderboard["source_ip"].apply(get_country)
        leaderboard = leaderboard[["source_ip","country","attacks","last_seen","max_risk"]]

    # Rank
    leaderboard.insert(0, "rank", range(1, len(leaderboard)+1))

    st.dataframe(leaderboard, use_container_width=True)
else:
    st.info("No attacker data")

# ---------------- RISK PANEL 🔥 ----------------
st.markdown("### 🚨 Risk Intelligence")

active_df = global_df if mode == "Global" else local_df

if not active_df.empty:
    risk_df = active_df.copy()

    risk_df['confidence'] = pd.to_numeric(risk_df['confidence'], errors='coerce').fillna(0)
    risk_df['risk'] = risk_df['confidence'].apply(risk_level)

    risk_df = risk_df.sort_values("timestamp", ascending=False)

    # 🔥 Add country only in global
    if mode == "Global":
        risk_df["country"] = risk_df["source_ip"].apply(get_country)
        st.dataframe(
            risk_df[['timestamp','source_ip','country','attack_type','risk']].head(20),
            use_container_width=True
        )
    else:
        st.dataframe(
            risk_df[['timestamp','source_ip','attack_type','risk']].head(20),
            use_container_width=True
        )

else:
    st.info("No risk data")

# ---------------- ALERTS 🔥 ----------------
if not events_df.empty:
    latest = events_df.sort_values("timestamp", ascending=False).iloc[0]

    if latest['confidence'] and latest['confidence'] > 0.8:
        st.error(f"🚨 HIGH ALERT: {latest['attack_type']} from {latest['source_ip']}")
