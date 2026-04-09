#!/usr/bin/env python3
import os
import json
import time
import joblib
import pandas as pd
import numpy as np
import warnings
import sys
import csv
from scapy.all import sniff, IP, UDP, get_if_addr, conf
from collections import defaultdict
from datetime import datetime
 
# 1. INTEGRATE UNIFIED DATABASE
sys.path.append('/home/vinayak/honeypot_project')
try:
    from honeypot_db import log_attack_and_ban
    print("[✓] Unified Database integration active")
except ImportError:
    print("[!] WARNING: honeypot_db.py not found.")
 
warnings.filterwarnings("ignore", category=UserWarning)
 
# ============================================================================
# CONFIGURATION
# ============================================================================
BASE_PATH = '/home/vinayak/honeypot_project/models/dns/'
MODEL_PATH = os.path.join(BASE_PATH, 'dns_model.joblib')
SCALER_PATH = os.path.join(BASE_PATH, 'dns_scalar.joblib')
FEATURES_PATH = os.path.join(BASE_PATH, 'dns_features.json')
LABELS_PATH = os.path.join(BASE_PATH, 'dns_labels.json')
# This is the main log the dashboard reads
MAIN_LOG = '/home/vinayak/honeypot_project/logs/security_events.csv'
 
DNS_PORT = 53
PACKET_THRESHOLD = 50
 
# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
 
def load_features_json():
    with open(FEATURES_PATH, 'r') as f:
        data = json.load(f)
    return data.get('features', []) if isinstance(data, dict) else data
 
def load_labels_json():
    with open(LABELS_PATH, 'r') as f:
        data = json.load(f)
    return {str(k): v for k, v in data.items()}
 
def smart_setter(data, feature_name, value):
    for variant in [feature_name, f" {feature_name}", f"{feature_name} ", f" {feature_name} "]:
        if variant in data:
            data[variant] = value
            return
    data[feature_name] = value

# --- SAFE INITIALIZATION ---
model = None
scaler = None
required_features = []
labels_dict = {}
# ============================================================================
# INITIALIZATION
# ============================================================================
print("\n" + "="*60 + "\n    IOT SENTRY | DNS ML DETECTOR\n" + "="*60)
 
try:
    MY_IP = get_if_addr("wlan0")
    print(f"[*] Monitoring Infection Zone (wlan0): {MY_IP}")
except Exception:
    MY_IP = "10.42.0.1" # Fallback for your hotspot
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    required_features = load_features_json()
    labels_dict = load_labels_json()
    print(f"[+] System Ready. Monitoring {MY_IP} for DNS DrDoS...")
except Exception as e:
    print(f"[!] Init failed: {e}")
    sys.exit(1)
 
flows = defaultdict(lambda: {
    'start_time': None, 'last_pkt_time': None, 'fwd_pkts': 0, 'bwd_pkts': 0,
    'fwd_lengths': [], 'bwd_lengths': [], 'all_iats': [], 'fwd_iats': [],
    'bwd_iats': [], 'blocked': False, 'analyzed': False
})
 
# ============================================================================
# ANALYSIS & LOGGING
# ============================================================================
 
def analyze_and_block(external_ip, flow_key):
    if flows[flow_key]['blocked']: return
 
    flow = flows[flow_key]
    total_packets = flow['fwd_pkts'] + flow['bwd_pkts']
    duration = float(flow['last_pkt_time']) - float(flow['start_time'])
    if duration <= 0: duration = 0.001
 
    data = {feat: 0 for feat in required_features}
    smart_setter(data, 'Flow Duration', int(duration * 1e6))
    smart_setter(data, 'Flow Packets/s', total_packets / duration)
 
    if flow['fwd_lengths']:
        smart_setter(data, 'Fwd Packet Length Mean', np.mean(flow['fwd_lengths']))
 
    # ML PREDICTION
    df = pd.DataFrame([data])[required_features].fillna(0)
    raw_pred = model.predict(df)[0]
    confidence = np.max(model.predict_proba(df)[0])
    attack_type = labels_dict.get(str(int(raw_pred)), "Unknown")
 
    # HEURISTIC OVERRIDE for High-Volume Reflection
    avg_pkt_size = np.mean(flow['fwd_lengths'] + flow['bwd_lengths'])
    if total_packets > 40 and avg_pkt_size > 200:
        attack_type = "DrDoS_DNS_Amplification"
        confidence = max(confidence, 0.95)
 
    if "DNS" in attack_type and confidence > 0.5:
        flows[flow_key]['blocked'] = True
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
 
        # 1. LOG TO DASHBOARD CSV (10 Columns)
        row = [timestamp, external_ip, attack_type, 53, "UDP", round(float(confidence), 2), 19.076, 72.877, "India", "Mumbai"]
        with open(MAIN_LOG, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(row)
 
        # 2. LOG TO SQLITE DATABASE
        log_attack_and_ban(external_ip, attack_type, 53, "UDP", float(confidence))
        print(f"[🚨 ALERT] DNS ATTACK BLOCKED: {external_ip} | Conf: {confidence:.2%}")
 
# ============================================================================
# PACKET PROCESSING
# ============================================================================
 
def packet_callback(pkt):
    if IP not in pkt or UDP not in pkt: return
    src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
    sport, dport = pkt[UDP].sport, pkt[UDP].dport
 
    if dst_ip == MY_IP and dport == DNS_PORT:
        flow_key = src_ip
        pkt_time = float(pkt.time)
        if flows[flow_key]['start_time'] is None: flows[flow_key]['start_time'] = pkt_time
        flows[flow_key]['last_pkt_time'] = pkt_time
        flows[flow_key]['fwd_pkts'] += 1
        flows[flow_key]['fwd_lengths'].append(len(pkt))
 
        if flows[flow_key]['fwd_pkts'] >= PACKET_THRESHOLD and not flows[flow_key]['analyzed']:
            flows[flow_key]['analyzed'] = True
            analyze_and_block(src_ip, flow_key)
 
if __name__ == "__main__":
    sniff(iface="wlan0", prn=packet_callback, store=False)
