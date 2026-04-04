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

# --- CUSTOM CSS (Cyber-Dark Theme) ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500&display=swap');
    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
    .stApp { background-color: #050505; background-image: radial-gradient(circle at 50% 0%, #171124 0%, #050505 50%); color: #e2e8f0; }
    .main-header { font-size: 2.2rem; background: linear-gradient(90deg, #3b82f6, #8b5cf6, #ec4899); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: 700; margin-bottom: 0px; }
    .status-badge { display: inline-block; padding: 0.3rem 0.8rem; border-radius: 50px; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.2); color: #10b981; font-size: 0.75rem; }
    .cyber-card { background: rgba(15, 23, 42, 0.5); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 8px; padding: 1rem; backdrop-filter: blur(10px); }
    .dataframe-container { border-radius: 12px; overflow: auto; max-height: 450px; border: 1px solid rgba(255, 255, 255, 0.05); background: rgba(15, 23, 42, 0.4); }
</style>
""", unsafe_allow_html=True)

ist = pytz.timezone('Asia/Kolkata')

@st.cache_data(ttl=10)
def fetch_logs(filename):
    try:
        df = pd.read_csv(RAW_URL + filename)
        return df
    except:
        return pd.DataFrame()

# Fetch Master Data
events_df = fetch_logs("security_events.csv")
banned_df = fetch_logs("banned_ips.csv")
traffic_df = fetch_logs("traffic_metrics.csv")
devices_df = fetch_logs("known_devices.csv")

# --- HEADER ---
c_h1, c_h2 = st.columns([2, 1])
with c_h1:
    st.markdown('<div class="main-header">Nexus Security Core</div>', unsafe_allow_html=True)
    st.markdown('<div class="status-badge">🟢 C2 CLOUD NODE ONLINE</div>', unsafe_allow_html=True)
with c_h2:
    st.markdown(f"<div style='text-align: right; color: #94a3b8; font-family: \"Fira Code\"; padding-top: 15px;'>{datetime.now(ist).strftime('%Y-%m-%d | %H:%M:%S')}</div>", unsafe_allow_html=True)

st.divider()

# --- TOP SECTION: NETWORK CENSUS & INVESTIGATION ---
st.markdown("### 📱 Active Network Census")
st.markdown("Select a device from the list to view its traffic history and manage its access.")

if not devices_df.empty:
    # Column selector for interaction
    col_list, col_investigate = st.columns([1, 1])
    
    with col_list:
        st.markdown("#### Discovered Assets")
        # Let the user pick a device
        selected_ip = st.selectbox("🎯 Target Selection for Investigation:", 
                                   options=devices_df['ip_address'].unique(),
                                   index=0)
        
        # Display the device list in a clean table
        st.dataframe(devices_df[['ip_address', 'mac_address', 'last_seen']], use_container_width=True, hide_index=True)

    with col_investigate:
        st.markdown(f"#### 🔍 Investigation: {selected_ip}")
        
        # Filter traffic for the selected IP
        if not events_df.empty:
            ip_traffic = events_df[events_df['source_ip'] == selected_ip]
            if not ip_traffic.empty:
                st.warning(f"⚠️ {len(ip_traffic)} Hostile events recorded for this IP.")
                st.dataframe(ip_traffic[['timestamp', 'attack_type', 'confidence']], use_container_width=True, hide_index=True)
            else:
                st.success("No hostile behavior detected for this asset.")
        
        # C2 Command for this specific IP
        st.markdown("---")
        with st.form("quick_block"):
            st.markdown(f"**Physical Isolation Request for {selected_ip}**")
            reason = st.selectbox("Reason", ["Unauthorized Device", "Confirmed Intrusion", "Suspicious Activity"])
            if st.form_submit_button("🚀 EXECUTE KERNEL BLOCK", use_container_width=True):
                try:
                    g = Github(st.secrets["GITHUB_TOKEN"])
                    repo = g.get_repo("vinayak-salian/honeypot-idps")
                    cmd = f"{selected_ip},{reason},{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    try:
                        contents = repo.get_contents("logs/block_queue.txt")
                        repo.update_file(contents.path, f"C2: Block {selected_ip}", contents.decoded_content.decode() + "\n" + cmd, contents.sha)
                    except:
                        repo.create_file("logs/block_queue.txt", "C2: Init Queue", cmd)
                    st.success(f"Command Sent: {selected_ip} will be isolated.")
                except Exception as e:
                    st.error(f"C2 Link Failure: {e}")
else:
    st.info("Searching for local hardware... Please ensure the Sentry Network Census is running on the Pi.")

st.divider()

# --- MIDDLE SECTION: THREAT FEED TABS ---
st.markdown("### 📡 Real-Time Threat Intelligence")
t1, t2, t3, t4 = st.tabs(["🎯 Port Scans", "🦠 Malware", "🔑 Brute Force", "🚫 Banned List"])

def simple_table(df):
    if not df.empty:
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("Monitoring for specific signatures...")

with t1:
    simple_table(events_df[events_df['attack_type'].str.contains('PortScan', na=False)] if not events_df.empty else pd.DataFrame())
with t2:
    simple_table(events_df[events_df['attack_type'].str.contains('Malware', na=False)] if not events_df.empty else pd.DataFrame())
with t3:
    simple_table(events_df[events_df['attack_type'].str.contains('Brute|Patator', na=False)] if not events_df.empty else pd.DataFrame())
with t4:
    simple_table(banned_df)

st.divider()

# --- BOTTOM SECTION: HISTORICAL DATA & HEATMAP ---
st.markdown("### 📜 Strategic Intelligence & Global Attribution")
c_map, c_hist = st.columns([1, 1])

with c_map:
    st.markdown("#### Threat Origins")
    if not events_df.empty and 'latitude' in events_df.columns:
        map_data = events_df.dropna(subset=['latitude', 'longitude'])
        st.map(map_data, latitude='latitude', longitude='longitude', color='#ec4899', size=40)
    else:
        st.info("Awaiting geospatial logs...")

with c_hist:
    st.markdown("#### Master Historical Archive")
    if not events_df.empty:
        st.dataframe(events_df.sort_values("timestamp", ascending=False), height=400, use_container_width=True, hide_index=True)
    else:
        st.info("Archive empty.")

st.markdown("<div style='text-align: center; color: #475569; padding-top: 50px;'>Nexus System Build v2.0.7 • Secure Remote C2 Link</div>", unsafe_allow_html=True)
