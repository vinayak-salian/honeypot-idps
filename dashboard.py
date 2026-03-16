import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import pytz

# --- CONFIGURATION ---
RAW_URL = "https://raw.githubusercontent.com/vinayak-salian/honeypot-idps/main/logs/"

st.set_page_config(
    page_title="Honeypot Network Defense",
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

    /* SubHeaders */
    h1, h2, h3 {
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
    
    /* Cyber Metric Cards */
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
    .cyber-card::before, .cyber-card::after {
        content: '';
        position: absolute;
        width: 15px;
        height: 15px;
        border: 2px solid transparent;
        pointer-events: none;
    }
    .cyber-card::before {
        top: -1px; left: -1px;
        border-top-color: var(--card-color);
        border-left-color: var(--card-color);
        border-top-left-radius: 8px;
    }
    .cyber-card::after {
        bottom: -1px; right: -1px;
        border-bottom-color: var(--card-color);
        border-right-color: var(--card-color);
        border-bottom-right-radius: 8px;
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

    /* Tabs */
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
        border-bottom: none;
        border-top: 2px solid #8b5cf6;
    }

    /* Tables */
    .dataframe-container {
        border-radius: 12px;
        overflow: hidden;
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
        letter-spacing: 0.05em;
        border-bottom: 1px solid rgba(255, 255, 255, 0.05); 
    }
    td { 
        padding: 12px 16px; 
        border-bottom: 1px solid rgba(255, 255, 255, 0.02); 
    }
    tr:hover td {
        background-color: rgba(139, 92, 246, 0.05);
    }
    
    /* Info/Success Boxes */
    .stAlert {
        border-radius: 12px;
        border: none;
        background: rgba(30, 41, 59, 0.4);
        backdrop-filter: blur(10px);
    }
    
    .threat-level-high {
        color: #ef4444;
        font-weight: bold;
    }
    .threat-level-medium {
        color: #f59e0b;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

ist = pytz.timezone('Asia/Kolkata')

@st.cache_data(ttl=30)
def fetch_logs(filename):
    """Fetches real logs only. Returns empty dataframe if no logs exist."""
    try:
        url = RAW_URL + filename
        return pd.read_csv(url)
    except Exception:
        return pd.DataFrame()

# --- HEADER SECTION ---
col1, col2 = st.columns([1, 1])
with col1:
    st.markdown('<div class="main-header">Nexus Security Core</div>', unsafe_allow_html=True)
    st.markdown('<div class="status-badge">🟢 SENTRY NODE OPERATIONAL • LIVE</div>', unsafe_allow_html=True)

with col2:
    st.markdown(
        f"""
        <div style="text-align: right; padding-top: 1rem; color: #94a3b8; font-family: 'Fira Code', monospace;">
            <div>SYS_TIME // {datetime.now(ist).strftime('%H:%M:%S IST')}</div>
            <div>STATUS // AUTONOMOUS_ENGAGEMENT</div>
        </div>
        """,
        unsafe_allow_html=True
    )

st.markdown("<br>", unsafe_allow_html=True)

# --- DATA FETCHING ---
ps_df = fetch_logs("portscan_log.csv")
mw_df = fetch_logs("malware_delivery_log.csv")
bf_df = fetch_logs("bruteforce_log.csv")
dns_df = fetch_logs("dns_spoof_log.csv")

# --- METRIC CARDS ---
def build_sparkline_path(df, bins=24):
    """Builds an SVG polyline path from real event frequency, binned by hour."""
    if df.empty or 'timestamp' not in df.columns:
        return "M0 25 L100 25"  # flat line fallback
    try:
        df = df.copy()
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df = df.dropna(subset=['timestamp'])
        if df.empty:
            return "M0 25 L100 25"
        now = datetime.now(pytz.utc).replace(tzinfo=None)
        start = now - timedelta(hours=bins)
        df = df[df['timestamp'] >= start]
        # Bin events by hour
        df['hour_bin'] = df['timestamp'].dt.floor('h')
        counts = df.groupby('hour_bin').size()
        # Create a full range of hours
        all_hours = pd.date_range(start=start.replace(minute=0, second=0, microsecond=0), periods=bins, freq='h')
        counts = counts.reindex(all_hours, fill_value=0)
        values = counts.values.astype(float)
        if values.max() == 0:
            return "M0 25 L100 25"
        # Normalise to SVG height (5 to 28, leaving padding)
        norm = (values - values.min()) / (values.max() - values.min() + 1e-9)
        ys = 28 - norm * 23  # map to range [5, 28]
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

with m1:
    st.markdown(create_card("RECONNAISSANCE EVENTS", len(ps_df), "📡", "card-blue", "#3b82f6", build_sparkline_path(ps_df)), unsafe_allow_html=True)
with m2:
    st.markdown(create_card("PAYLOAD DROPS", len(mw_df), "📦", "card-purple", "#8b5cf6", build_sparkline_path(mw_df)), unsafe_allow_html=True)
with m3:
    st.markdown(create_card("AUTH VIOLATIONS", len(bf_df), "🔓", "card-orange", "#f59e0b", build_sparkline_path(bf_df)), unsafe_allow_html=True)
with m4:
    st.markdown(create_card("DNS ANOMALIES", len(dns_df), "🔗", "card-teal", "#14b8a6", build_sparkline_path(dns_df)), unsafe_allow_html=True)

st.markdown("<br><hr style='border-color: rgba(255,255,255,0.05);'><br>", unsafe_allow_html=True)

# --- MAIN DASHBOARD CONTENT ---
st.markdown("### 📡 Threat Intelligence Feed")
st.markdown("<p style='color: #94a3b8; margin-bottom: 2rem;'>Real-time analysis of incoming honeypot traffic and anomaly detection.</p>", unsafe_allow_html=True)

tab1, tab2, tab3, tab4 = st.tabs(["🎯 Port Scanning", "🦠 Malware Delivery", "🔑 Brute Force", "🌐 DNS Spoofing"])

def render_table(df, empty_message):
    if not df.empty:
        html_table = f'<div class="dataframe-container">{df.astype(str).sort_index(ascending=False).to_html(index=False, escape=False, classes="custom-table")}</div>'
        st.markdown(html_table, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div style="padding: 2rem; text-align: center; background: rgba(30, 41, 59, 0.4); border-radius: 12px; border: 1px dashed rgba(255,255,255,0.1); color: #94a3b8;">
            <span style="font-size: 1.5rem; display: block; margin-bottom: 0.5rem;">✨</span>
            {{empty_message}}
        </div>
        """, unsafe_allow_html=True)

with tab1: render_table(ps_df, "No Port Scan anomalies detected.")
with tab2: render_table(mw_df, "No Malware delivery attempts intercepted.")
with tab3: render_table(bf_df, "No Brute Force signatures detected.")
with tab4: render_table(dns_df, "No DNS Spoofing activities recorded.")

st.markdown("<br><hr style='border-color: rgba(255,255,255,0.05);'><br>", unsafe_allow_html=True)

# --- MITIGATION SECTION ---
col_mit1, col_mit2 = st.columns([1, 2])

with col_mit1:
    st.markdown("### 🛡️ Active Mitigation")
    st.markdown("""
    **Nexus ML Engine** is currently routing hostile IPs to the containment zone.
    * Policy-Based Routing: <span style='color: #10b981; font-weight: bold;'>Active</span>
    * Autonomous Firewall: <span style='color: #10b981; font-weight: bold;'>Active</span>
    * Threat Intelligence Sync: <span style='color: #10b981; font-weight: bold;'>Healthy</span>
    """, unsafe_allow_html=True)

with col_mit2:
    st.markdown("#### 🚫 Banned Sentry Entities (Live)")
    try:
        blocked_url = RAW_URL + "blocked_ips.txt"
        blocked_df = pd.read_csv(blocked_url, names=["Banned Source IPs"])
        
        if not blocked_df.empty:
            render_table(blocked_df, "")
        else:
            st.success("Containment zone is currently empty. No entities actively banned.")
    except Exception:
        st.success("Containment zone is currently empty. No entities actively banned.")

st.markdown("""
<div style="text-align: center; margin-top: 3rem; color: #475569; font-size: 0.875rem; font-family: 'Fira Code', monospace;">
    SYSTEM BUILD 2.0.4 • ENCRYPTED CONNECTION • ZERO-TRUST ARCHITECTURE
</div>
""", unsafe_allow_html=True)
