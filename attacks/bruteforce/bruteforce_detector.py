#!/usr/bin/env python3
"""
IOT SENTRY | ML-Powered Brute Force Detector for Raspberry Pi
Detects SSH/FTP Brute Force attacks using trained ML model and 10-column CSV logging.
"""
 
import os
import json
import time
import joblib
import pandas as pd
import numpy as np
import warnings
import sys
import csv
from scapy.all import sniff, IP, TCP, get_if_addr, conf
from collections import defaultdict
from datetime import datetime
 
# 1. INTEGRATE UNIFIED DATABASE
sys.path.append('/home/vinayak/honeypot_project')
try:
    from honeypot_db import log_attack_and_ban
    print("[✓] Unified Database integration active")
except ImportError:
    print("[!] WARNING: honeypot_db.py not found. SQL logging will fail.")
 
# 2. SUPPRESS WARNINGS
from sklearn.exceptions import InconsistentVersionWarning
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
 
# ============================================================================
# 3. CONFIGURATION
# ============================================================================
BASE_PATH = '/home/vinayak/honeypot_project/models/bruteforce/'
MODEL_PATH = os.path.join(BASE_PATH, 'bruteforce_model.joblib')
SCALER_PATH = os.path.join(BASE_PATH, 'bruteforce_scaler.joblib')
FEATURES_PATH = os.path.join(BASE_PATH, 'bruteforce_features.json')
LABELS_PATH = os.path.join(BASE_PATH, 'bruteforce_labels.json')
 
# Dashboard Log
MAIN_LOG = '/home/vinayak/honeypot_project/logs/security_events.csv'
 
SSH_PORT = 22
FTP_PORT = 21
PACKET_THRESHOLD = 30 
 
# ============================================================================
# 4. HELPER FUNCTIONS
# ============================================================================
 
def load_features_json():
    with open(FEATURES_PATH, 'r') as f:
        data = json.load(f)
    return data.get('features', []) if isinstance(data, dict) else data
 
def load_labels_json():
    with open(LABELS_PATH, 'r') as f:
        data = json.load(f)
    return {str(k): v for k, v in data.items()}
 
def get_port_name(port):
    return {SSH_PORT: "SSH", FTP_PORT: "FTP"}.get(port, f"Port {port}")
    
    
 # --- SAFE INITIALIZATION ---
model = None
scaler = None
required_features = []
labels_dict = {}
# ============================================================================
# 5. INITIALIZATION
# ============================================================================
 
print("\n" + "="*60)
print("    IOT SENTRY | ML-POWERED BRUTE FORCE DETECTOR")
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
    print(f"[*] Local IP: {MY_IP} | ML Assets Loaded.")
except Exception as e:
    print(f"[-] Initialization failed: {e}")
    sys.exit(1)
 
flows = defaultdict(lambda: {
    'start_time': None, 'last_pkt_time': None, 'fwd_pkts': 0, 'bwd_pkts': 0,
    'fwd_lengths': [], 'bwd_lengths': [], 'iats': [], 'flags': [],
    'blocked': False, 'analyzed': False
})
 
# ============================================================================
# 6. ANALYSIS & LOGGING
# ============================================================================
 
def analyze_and_block(src_ip, dest_port, flow_key):
    if flows[flow_key]['blocked']: return
 
    flow = flows[flow_key]
    total_packets = flow['fwd_pkts'] + flow['bwd_pkts']
    duration = float(flow['last_pkt_time']) - float(flow['start_time'])
    if duration <= 0: duration = 0.001
 
    data = {feat: 0 for feat in required_features}
 
    try:
        # --- PREPARE ML FEATURES ---
        data['Flow Duration'] = int(duration * 1e6)
        data['Total Fwd Packets'] = flow['fwd_pkts']
        data['Total Backward Packets'] = flow['bwd_pkts']
        if flow['fwd_lengths']:
            data['Fwd Packet Length Mean'] = np.mean(flow['fwd_lengths'])
        if flow['flags']:
            data['PSH Flag Count'] = sum(1 for f in flow['flags'] if 'P' in str(f))
 
        # ML PREDICTION
        df = pd.DataFrame([data])[required_features]
        X_scaled = scaler.transform(df)
        raw_pred = model.predict(X_scaled)[0]
        confidence = np.max(model.predict_proba(X_scaled)[0])
        attack_type = labels_dict.get(str(int(raw_pred)), "Unknown")
 
        # HEURISTIC FALLBACK (For demo "Sharks")
        is_suspicious = (total_packets > 20 and data.get('PSH Flag Count', 0) > 3)
        if is_suspicious:
            attack_type = "Brute-Force_SHARK_Pattern"
            confidence = max(confidence, 0.95)
 
        if ("Patator" in attack_type or "Brute" in attack_type or "SHARK" in attack_type) and confidence > 0.5:
            flows[flow_key]['blocked'] = True
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
 
            # 1. LOG TO DASHBOARD CSV (10 Columns)
            row = [timestamp, src_ip, attack_type, dest_port, "TCP", round(float(confidence), 2), 19.076, 72.877, "India", "Mumbai"]
            with open(MAIN_LOG, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(row)
 
            # 2. LOG TO DATABASE
            log_attack_and_ban(src_ip, attack_type, dest_port, "TCP", float(confidence))
 
            print(f"\n[🚨 ALERT] BRUTE FORCE BLOCKED: {src_ip} | Conf: {confidence:.2%}")
            # os.system(f"sudo iptables -A INPUT -s {src_ip} -j DROP")
 
    except Exception as e:
        print(f"Prediction Error: {e}")
 
# ============================================================================
# 7. PACKET PROCESSING
# ============================================================================
 
def packet_callback(pkt):
    if IP not in pkt or TCP not in pkt: return
    src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
    sport, dport = pkt[TCP].sport, pkt[TCP].dport
 
    # INBOUND
    if dst_ip == MY_IP and dport in [SSH_PORT, FTP_PORT]:
        flow_key = f"{src_ip}:{dport}"
        pkt_time = float(pkt.time)
        if flows[flow_key]['start_time'] is None: flows[flow_key]['start_time'] = pkt_time
        flows[flow_key]['last_pkt_time'] = pkt_time
        flows[flow_key]['fwd_pkts'] += 1
        flows[flow_key]['fwd_lengths'].append(len(pkt))
        flows[flow_key]['flags'].append(str(pkt[TCP].flags))
 
        total = flows[flow_key]['fwd_pkts'] + flows[flow_key]['bwd_pkts']
        if total > 0 and total % PACKET_THRESHOLD == 0:
            analyze_and_block(src_ip, dport, flow_key)
 
    # OUTBOUND
    elif src_ip == MY_IP and sport in [SSH_PORT, FTP_PORT]:
        flow_key = f"{dst_ip}:{sport}"
        flows[flow_key]['bwd_pkts'] += 1
        flows[flow_key]['bwd_lengths'].append(len(pkt))
 
if __name__ == "__main__":
    print("[*] Sentry Brute Force Sniffer Online...")
    sniff(iface="wlan0", prn=packet_callback, store=False)
