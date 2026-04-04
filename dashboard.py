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

# --- CUSTOM CSS ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    .stApp {
        background-color: #050505;
        background-image: radial-gradient(circle at 50% 0%, #171124 0%, #050505 50%);
        color: #e2e8f0;
    }

    h1, h2, h3, h4 {
        color: #f8fafc;
        font-weight: 600 !important;
        letter-spacing: -0.025em;
    }
    
    .main-header {
        font-size: 2.5rem;
        background: linear-gradient(90deg, #3b82f6, #8b5cf6, #ec4899);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0rem;
        padding-bottom: 0rem;
        font-weight: 700;
    }
    
    .status-badge {
        display: inline-block;
        padding: 0.35rem 1rem;
        border-radius: 50px;
        background: rgba(16, 185, 129, 0.1);
        border: 1px solid rgba(16, 185, 129, 0.2);
        color: #10b981;
        font-size: 0.875rem;
        font-weight: 500;
        margin-top: 1rem;
        box-shadow: 0 0 15px rgba(16, 185, 129, 0.1);
    }
    
    .cyber-card {
        background: rgba(15, 23, 42, 0.5);
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-radius: 8px; 
        padding: 1.25rem;
        position: relative;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        backdrop-filter: blur(10px);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    .cyber-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 15px -3px rgba(0, 0, 0, 0.2);
    }
    .card-blue { --card-color: #3b82f6; }
    .card-purple { --card-color: #8b5cf6; }
    .card-orange { --card-color: #f59e0b; }
    .card-teal { --card-color: #14b8a6; }
    
    .cyber-card-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.75rem;
    }
    .cyber-card-title {
        font-size: 0.75rem;
        color: #cbd5e1;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .cyber-card-icon {
        font-size: 1.2rem;
        opacity: 0.8;
    }
    .cyber-card-body {
        display: flex;
        justify-content: space-between;
        align-items: flex-end;
    }
    .cyber-card-value {
        font-size: 2.25rem;
        font-weight: 700;
        color: #f8fafc;
        line-height: 1;
        font-family: 'Fira Code', monospace;
    }
    .cyber-card-chart {
        width: 80px;
        height: 30px;
    }

    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: transparent;
    }
    .stTabs [data-baseweb="tab"] {
        height: 40px;
        white-space: pre-wrap;
        background-color: rgba(30, 41, 59, 0.3);
        border-radius: 8px 8px 0 0;
        color: #94a3b8;
        border: 1px solid transparent;
        border-bottom: none;
        padding: 0 16px;
    }
    .stTabs [aria-selected="true"] {
        background-color: rgba(30, 41, 59, 1);
        color: #f8fafc;
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-top: 2px solid #8b5cf6;
    }

    .dataframe-container {
        border-radius: 12px;
        overflow: auto;
        max-height: 400px;
        border: 1px solid rgba(255, 255, 255, 0.05);
        background: rgba(15, 23, 42, 0.4);
        backdrop-filter: blur(10px);
    }
    table { 
        width: 100%; 
        border-collapse: collapse; 
        font-size: 0.875rem; 
        font-family: 'Fira Code', monospace;
        color: #cbd5e1;
    }
    th { 
        text-align: left; 
        padding: 12px 16px; 
        background-color: rgba(30, 41, 59, 0.8); 
        color: #f8fafc;
        font-weight: 500;
        text-transform: uppercase;
        font-size: 0.75rem;
        border-bottom: 1px solid rgba(255, 255, 255, 0.05); 
        position: sticky;
        top: 0;
    }
    td { 
        padding: 12px 16px; 
        border-bottom: 1px solid rgba(255, 255, 255, 0.02); 
    }
    tr:hover td {
        background-color: rgba(139, 92, 246, 0.05);
    }
</style>
""", unsafe_allow_html=True)

ist = pytz.timezone('Asia/Kolkata')

# --- DATA FETCHING (From GitHub) ---
@st.cache_data(ttl=30)
def fetch_logs(filename):
    try:
        url = RAW_URL + filename
        return pd.read_csv(url)
    except Exception:
        return pd.DataFrame()

# Fetch Master Tables from GitHub
events_df = fetch_logs("security_events.csv")
banned_df = fetch_logs("banned_ips.csv")
traffic_df = fetch_logs("traffic_metrics.csv")

if not events_df.empty and 'attack_type' in events_df.columns:
    ps_df = events_df[events_df['attack_type'].str.contains('PortScan', case=False, na=False)]
    mw_df = events_df[events_df['attack_type'].str.contains('Malware', case=False, na=False)]
    bf_df = events_df[events_df['attack_type'].str.contains('Brute|Patator', case=False, na=False)]
    dns_df = events_df[events_df['attack_type'].str.contains('DNS|DrDoS', case=False, na=False)]
else:
    ps_df = mw_df = bf_df = dns_df = pd.DataFrame()

# --- HEADER SECTION ---
col1, col2 = st.columns([1, 1])
with col1:
    st.markdown('<div class="main-header">Nexus Security Core</div>', unsafe_allow_html=True)
    st.markdown('<div class="status-badge">🟢 C2 CLOUD DASHBOARD • SYNCHRONIZED</div>', unsafe_allow_html=True)

with col2:
    st.markdown(
        f"""
        <div style="text-align: right; padding-top: 1rem; color: #94a3b8; font-family: 'Fira Code', monospace;">
            <div>SYS_TIME // {datetime.now(ist).strftime('%H:%M:%S IST')}</div>
            <div>STATUS // REMOTE_COMMAND_READY</div>
        </div>
        """,
        unsafe_allow_html=True
    )

st.markdown("<br>", unsafe_allow_html=True)

# --- METRIC CARDS ---
def build_sparkline_path(df, bins=24):
    if df.empty or 'timestamp' not in df.columns:
        return "M0 25 L100 25"
    try:
        df = df.copy()
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df = df.dropna(subset=['timestamp'])
        if df.empty: return "M0 25 L100 25"
        now = datetime.now(pytz.utc).replace(tzinfo=None)
        start = now - timedelta(hours=bins)
        df = df[df['timestamp'] >= start]
        df['hour_bin'] = df['timestamp'].dt.floor('h')
        counts = df.groupby('hour_bin').size()
        all_hours = pd.date_range(start=start.replace(minute=0, second=0, microsecond=0), periods=bins, freq='h')
        counts = counts.reindex(all_hours, fill_value=0)
        values = counts.values.astype(float)
        if values.max() == 0: return "M0 25 L100 25"
        norm = (values - values.min()) / (values.max() - values.min() + 1e-9)
        ys = 28 - norm * 23
        xs = np.linspace(0, 100, len(ys))
        points = " L".join(f"{x:.1f} {y:.1f}" for x, y in zip(xs, ys))
        return f"M{points.lstrip('M')}"
    except Exception:
        return "M0 25 L100 25"

def create_card(title, value, icon, color_class, sparkline_color, path_d):
    sparkline_svg = f"""<svg viewBox="0 0 100 30" preserveAspectRatio="none" style="width:100%;height:30px;"><path d="{path_d}" fill="none" stroke="{sparkline_color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>"""
    html = f"""
    <div class="cyber-card {color_class}">
        <div class="cyber-card-header">
            <span class="cyber-card-title">{title}</span>
            <span class="cyber-card-icon">{icon}</span>
        </div>
        <div class="cyber-card-body">
            <span class="cyber-card-value">{value}</span>
            <div class="cyber-card-chart">
                {sparkline_svg}
            </div>
        </div>
    </div>
    """
    return html

m1, m2, m3, m4 = st.columns(4)
with m1: st.markdown(create_card("RECONNAISSANCE", len(ps_df), "📡", "card-blue", "#3b82f6", build_sparkline_path(ps_df)), unsafe_allow_html=True)
with m2: st.markdown(create_card("PAYLOAD DROPS", len(mw_df), "📦", "card-purple", "#8b5cf6", build_sparkline_path(mw_df)), unsafe_allow_html=True)
with m3: st.markdown(create_card("AUTH VIOLATIONS", len(bf_df), "🔓", "card-orange", "#f59e0b", build_sparkline_path(bf_df)), unsafe_allow_html=True)
with m4: st.markdown(create_card("DNS ANOMALIES", len(dns_df), "🔗", "card-teal", "#14b8a6", build_sparkline_path(dns_df)), unsafe_allow_html=True)

st.markdown("<br><hr style='border-color: rgba(255,255,255,0.05);'><br>", unsafe_allow_html=True)

# --- GLOBAL THREAT MAP & TRAFFIC METRICS ---
col_map, col_traffic = st.columns([2, 1])

with col_map:
    st.markdown("### 🌍 Global Threat Heatmap")
    st.markdown("<p style='color: #94a3b8; margin-bottom: 1rem;'>Live geospatial visualization of hostile origins.</p>", unsafe_allow_html=True)
    
    if not events_df.empty and 'latitude' in events_df.columns and 'longitude' in events_df.columns:
        map_df = events_df[(events_df['latitude'].astype(float) != 0.0) & (events_df['longitude'].astype(float) != 0.0)].dropna(subset=['latitude', 'longitude'])
        if not map_df.empty:
            st.map(map_df, latitude='latitude', longitude='longitude', size=40, color='#ec4899', zoom=1)
        else:
            st.info("Awaiting geospatial threat data...")
    else:
        st.info("Awaiting geospatial threat data...")

with col_traffic:
    st.markdown("### 📊 Network Heartbeat")
    st.markdown("<p style='color: #94a3b8; margin-bottom: 1rem;'>Recent packet tally snapshot.</p>", unsafe_allow_html=True)
    
    if not traffic_df.empty:
        latest = traffic_df.iloc[0]
        st.markdown(f"""
        <div style="background: rgba(30, 41, 59, 0.4); padding: 1.5rem; border-radius: 8px; border: 1px solid rgba(255,255,255,0.05);">
            <div style="margin-bottom: 10px;"><strong>TCP Packets:</strong> <span style="color: #3b82f6; font-family: 'Fira Code'; float: right;">{latest.get('tcp_count', 0)}</span></div>
            <div style="margin-bottom: 10px;"><strong>UDP Packets:</strong> <span style="color: #8b5cf6; font-family: 'Fira Code'; float: right;">{latest.get('udp_count', 0)}</span></div>
            <div style="margin-bottom: 10px;"><strong>ICMP Packets:</strong> <span style="color: #f59e0b; font-family: 'Fira Code'; float: right;">{latest.get('icmp_count', 0)}</span></div>
            <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid rgba(255,255,255,0.1);">
                <strong>Bandwidth:</strong> <span style="color: #10b981; font-family: 'Fira Code'; float: right;">{latest.get('total_bytes', 0)} bytes</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.info("Awaiting traffic telemetry...")

st.markdown("<br><hr style='border-color: rgba(255,255,255,0.05);'><br>", unsafe_allow_html=True)

# --- MAIN DASHBOARD CONTENT ---
st.markdown("### 📡 Threat Intelligence Feed")
tab1, tab2, tab3, tab4 = st.tabs(["🎯 Port Scanning", "🦠 Malware Delivery", "🔑 Brute Force", "🌐 DNS Spoofing"])

def render_table(df, empty_message):
    if not df.empty:
        display_df = df.drop(columns=['latitude', 'longitude', 'id'], errors='ignore')
        html_table = f'<div class="dataframe-container">{display_df.astype(str).to_html(index=False, escape=False, classes="custom-table")}</div>'
        st.markdown(html_table, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div style="padding: 2rem; text-align: center; background: rgba(30, 41, 59, 0.4); border-radius: 12px; border: 1px dashed rgba(255,255,255,0.1); color: #94a3b8;">
            <span style="font-size: 1.5rem; display: block; margin-bottom: 0.5rem;">✨</span>
            {empty_message}
        </div>
        """, unsafe_allow_html=True)

with tab1: render_table(ps_df, "No Port Scan anomalies detected.")
with tab2: render_table(mw_df, "No Malware delivery attempts intercepted.")
with tab3: render_table(bf_df, "No Brute Force signatures detected.")
with tab4: render_table(dns_df, "No DNS Spoofing activities recorded.")

st.markdown("<br><hr style='border-color: rgba(255,255,255,0.05);'><br>", unsafe_allow_html=True)

# --- MITIGATION SECTION (C2 QUEUE LOGIC) ---
col_mit1, col_mit2 = st.columns([1, 2])

with col_mit1:
    st.markdown("### 🛡️ Active Mitigation")
    st.markdown(f"""
    **Nexus ML Engine Status:**
    * C2 Link: <span style='color: #10b981; font-weight: bold;'>ESTABLISHED</span>
    * Polling Interval: <span style='color: #8b5cf6; font-weight: bold;'>10 Seconds</span>
    * Remote IP Drop: <span style='color: #10b981; font-weight: bold;'>Active</span>
    """, unsafe_allow_html=True)

    st.markdown("<br>#### ⚡ Remote Manual Override", unsafe_allow_html=True)
    st.markdown("<p style='font-size: 0.8rem; color: #94a3b8;'>Queue an IP for kernel-level dropping on the remote Sentry Node.</p>", unsafe_allow_html=True)
    
    with st.form("manual_ban_form", clear_on_submit=True):
        target_ip = st.text_input("Target IPv4 Address:", placeholder="192.168.x.x")
        ban_reason = st.selectbox("Reason:", ["Manual Intervention (C2)", "Confirmed PortScan", "Confirmed BruteForce", "Confirmed Malware"])
        submit_ban = st.form_submit_button("QUEUE ISOLATION COMMAND", use_container_width=True)
        
        if submit_ban and target_ip:
            try:
                # Retrieve the GitHub token from Streamlit secrets
                github_token = st.secrets["GITHUB_TOKEN"]
                g = Github(github_token)
                repo = g.get_repo("vinayak-salian/honeypot-idps")
                
                new_entry = f"{target_ip},{ban_reason},{datetime.now(ist).strftime('%Y-%m-%d %H:%M:%S')}"
                
                try:
                    contents = repo.get_contents("logs/block_queue.txt")
                    current_queue = contents.decoded_content.decode()
                    new_queue = current_queue + f"\n{new_entry}"
                    repo.update_file(contents.path, f"C2: Queued IP {target_ip}", new_queue, contents.sha)
                except Exception:
                    # If file doesn't exist, create it
                    repo.create_file("logs/block_queue.txt", f"C2: Initialized queue with {target_ip}", new_entry)
                
                st.success(f"Command queued! The remote Pi will fetch and block {target_ip} within 10 seconds.")
            except Exception as e:
                st.error("C2 Link Failed. Did you set GITHUB_TOKEN in Streamlit Secrets?")

with col_mit2:
    st.markdown("#### 🚫 Banned Sentry Entities (Historical)")
    if not banned_df.empty:
        render_table(banned_df, "")
    else:
        st.success("Containment zone is currently empty. No entities actively banned.")

st.markdown("""
<div style="text-align: center; margin-top: 3rem; color: #475569; font-size: 0.875rem; font-family: 'Fira Code', monospace;">
    SYSTEM BUILD 2.0.4 • REMOTE C2 ARCHITECTURE • ZERO-TRUST
</div>
""", unsafe_allow_html=True)
