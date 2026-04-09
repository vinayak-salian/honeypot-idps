#!/usr/bin/env python3
"""
IOT SENTRY | ML-Powered Port Scan Detector for Raspberry Pi
Detects scanning using micro-flow hardware timestamps and 10-column CSV logging.
"""
 
import os
import json
import time
import joblib
import pandas as pd
import numpy as np
import warnings
import csv
from scapy.all import sniff, IP, TCP, get_if_addr, conf
from collections import defaultdict
from datetime import datetime
 
warnings.filterwarnings("ignore", category=UserWarning)
 
# ============================================================================
# CONFIGURATION
# ============================================================================
BASE_PATH = '/home/vinayak/honeypot_project/models/portscanning/'
MODEL_PATH = os.path.join(BASE_PATH, 'portscanning_model.joblib')
SCALER_PATH = os.path.join(BASE_PATH, 'portscanning_scaler.joblib')
FEATURES_PATH = os.path.join(BASE_PATH, 'portscanning_features.json')
LABELS_PATH = os.path.join(BASE_PATH, 'portscanning_labels.json')
 
# Dashboard Log
MAIN_LOG = '/home/vinayak/honeypot_project/logs/security_events.csv'
 
ATTACK_THRESHOLD = 5 
 
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
 
# --- SAFE INITIALIZATION ---
model = None
scaler = None
required_features = [] # Ensures this name always exists
labels_dict = {}
# ============================================================================
# INITIALIZATION
# ============================================================================
 
print("\n" + "="*60)
print("    IOT SENTRY | ML-POWERED PORT SCAN DETECTOR")
print("="*60)
 
try:
    MY_IP = get_if_addr("wlan0")
    print(f"[*] Monitoring Infection Zone (wlan0): {MY_IP}")
except Exception:
    MY_IP = "10.42.0.1" # Fallback for your hotspot
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    required_features = load_features_json()
    labels_dict = load_labels_json()
    print(f"[+] System Ready. Monitoring {MY_IP} for scanners.")
except Exception as e:
    print(f"[-] Init failed: {e}")
    exit()
 
flows = defaultdict(lambda: {
    'start_time': None, 'last_pkt_time': None, 'dest_ports': set(),
    'port_times': {}, 'port_packets': {}, 'port_flags': {},
    'blocked': False, 'analyzed': False
})
 
# ============================================================================
# ANALYSIS & LOGGING
# ============================================================================
 
def analyze_and_block(src_ip):
    if flows[src_ip]['blocked']: return
 
    flow = flows[src_ip]
    unique_ports = len(flow['dest_ports'])
    duration = float(flow['last_pkt_time']) - float(flow['start_time'])
    if duration <= 0: duration = 0.001
 
    # Initialize micro-flow features
    data = {feat: 0 for feat in required_features}
    data[' Destination Port'] = float(list(flow['dest_ports'])[-1])
    data[' Flow Duration'] = int(duration * 1e6)
    data[' Flow Packets/s'] = unique_ports / duration
 
    try:
        # ML PREDICTION
        df = pd.DataFrame([data])[required_features]
        X_scaled = scaler.transform(df)
        raw_pred = model.predict(X_scaled)[0]
        confidence = np.max(model.predict_proba(X_scaled)[0])
        attack_type = labels_dict.get(str(int(raw_pred)), "Unknown")
 
        # HEURISTIC BLOCK (For quick demo response)
        is_aggressive = (unique_ports >= 5 and data[' Flow Packets/s'] > 5.0)
 
        if (attack_type == "PortScan" and confidence > 0.5) or is_aggressive:
            flows[src_ip]['blocked'] = True
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
 
            # LOG TO DASHBOARD CSV (10 Columns)
            row = [timestamp, src_ip, "PortScan_ML_Detected", unique_ports, "TCP", round(float(confidence), 2), 19.076, 72.877, "India", "Mumbai"]
            with open(MAIN_LOG, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(row)
 
            print(f"\n[🚨 ALERT] PORT SCAN BLOCKED: {src_ip} | Ports: {unique_ports}")
            os.system(f"sudo iptables -A INPUT -s {src_ip} -j DROP")
 
    except Exception as e:
        print(f"Analysis Error: {e}")
 
# ============================================================================
# PACKET PROCESSING
# ============================================================================
 
def packet_callback(pkt):
    if IP not in pkt or TCP not in pkt: return
    src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
 
    if dst_ip == MY_IP:
        pkt_time = float(pkt.time)
        dest_port = pkt[TCP].dport
 
        if flows[src_ip]['start_time'] is None:
            flows[src_ip]['start_time'] = pkt_time
        flows[src_ip]['last_pkt_time'] = pkt_time
        flows[src_ip]['dest_ports'].add(dest_port)
 
        if len(flows[src_ip]['dest_ports']) >= ATTACK_THRESHOLD and not flows[src_ip]['analyzed']:
            flows[src_ip]['analyzed'] = True
            analyze_and_block(src_ip)
 
if __name__ == "__main__":
    print("[*] Sentry Port Scan Sniffer Online...")
    sniff(iface="wlan0", prn=packet_callback, store=False)
