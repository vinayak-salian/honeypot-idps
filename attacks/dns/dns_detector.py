#!/usr/bin/env python3
"""
IOT SENTRY | ML-Powered DNS DrDoS Detector for Raspberry Pi
Detects DNS Amplification (DrDoS) attacks using XGBoost model
Focuses on UDP Port 53 high-volume reflection attacks
"""
 
import os
import json
import time
import joblib
import pandas as pd
import numpy as np
import warnings
import sys  # Added for database integration
from scapy.all import sniff, IP, UDP, get_if_addr, conf
from collections import defaultdict
from datetime import datetime
 
# 1. INTEGRATE UNIFIED DATABASE
sys.path.append('/home/vinayak/honeypot_project')
try:
    from honeypot_db import log_attack_and_ban
    print("[✓] Unified Database integration active")
except ImportError:
    print("[!] WARNING: honeypot_db.py not found. Central logging will fail.")
 
# 2. SUPPRESS WARNINGS
warnings.filterwarnings("ignore", category=UserWarning)
 
# 3. CHECK XGBOOST AVAILABILITY
try:
    import xgboost
    print("[✓] XGBoost available")
except ImportError:
    print("[!] WARNING: XGBoost not installed!")
 
# ============================================================================
# 4. CONFIGURATION
# ============================================================================
BASE_PATH = '/home/vinayak/honeypot_project/models/dns/'
MODEL_PATH = os.path.join(BASE_PATH, 'dns_model.joblib')
SCALER_PATH = os.path.join(BASE_PATH, 'dns_scalar.joblib')
FEATURES_PATH = os.path.join(BASE_PATH, 'dns_features.json')
LABELS_PATH = os.path.join(BASE_PATH, 'dns_labels.json')
LOG_FILE = '/home/vinayak/honeypot_project/logs/dns_log.csv'
DEBUG_LOG = '/home/vinayak/honeypot_project/logs/dns_debug.txt'
 
DNS_PORT = 53
 
# ============================================================================
# 5. HELPER FUNCTIONS
# ============================================================================
 
def init_log_file():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w') as f:
            f.write("Timestamp,Source_IP,Attack_Type,Packet_Count,Avg_Packet_Size,Flow_Packets_Per_Sec,Confidence\n")
 
def debug_log(message):
    os.makedirs(os.path.dirname(DEBUG_LOG), exist_ok=True)
    with open(DEBUG_LOG, 'a') as f:
        f.write(f"[{datetime.now()}] {message}\n")
 
def load_features_json():
    with open(FEATURES_PATH, 'r') as f:
        data = json.load(f)
    if isinstance(data, dict):
        return data.get('features', [])
    return data
 
def load_labels_json():
    with open(LABELS_PATH, 'r') as f:
        data = json.load(f)
    return {str(k): v for k, v in data.items()}
 
def smart_setter(data, feature_name, value):
    if feature_name in data:
        data[feature_name] = value
        return
    if f" {feature_name}" in data:
        data[f" {feature_name}"] = value
        return
    if f"{feature_name} " in data:
        data[f"{feature_name} "] = value
        return
    if f" {feature_name} " in data:
        data[f" {feature_name} "] = value
        return
    data[feature_name] = value
 
# ============================================================================
# 6. INITIALIZATION
# ============================================================================
 
print("\n" + "="*60)
print("    IOT SENTRY | ML-POWERED DNS DDoS DETECTOR")
print("="*60)
 
try:
    MY_IP = get_if_addr(conf.iface)
    print(f"[*] Interface: {conf.iface}")
    print(f"[*] Local IP:  {MY_IP}")
except Exception as e:
    print(f"[!] Network Error: {e}")
    exit()
 
model = None
label_encoder = None
required_features = None
labels_dict = None
heuristic_only_mode = False
 
try:
    print("[*] Loading ML Assets...")
    model = joblib.load(MODEL_PATH)
    label_encoder = joblib.load(SCALER_PATH)
    required_features = load_features_json()
    labels_dict = load_labels_json()
    print(f"[+] ML Assets loaded successfully.\n")
except Exception as e:
    print(f"[!] WARNING: ML Model loading failed! Switching to HEURISTIC-ONLY mode.")
    heuristic_only_mode = True
    labels_dict = {"0": "BENIGN", "1": "DrDoS_DNS"}
 
init_log_file()
 
# ============================================================================
# 7. FLOW TRACKING DATA STRUCTURES
# ============================================================================
 
flows = defaultdict(lambda: {
    'start_time': None,
    'last_pkt_time': None,
    'last_fwd_time': None,
    'last_bwd_time': None,
    'fwd_pkts': 0,
    'bwd_pkts': 0,
    'fwd_lengths': [],
    'bwd_lengths': [],
    'all_iats': [],
    'fwd_iats': [],
    'bwd_iats': [],
    'blocked': False,
    'analyzed': False
})
 
PACKET_THRESHOLD = 50
 
# ============================================================================
# 8. ANALYSIS & BLOCKING
# ============================================================================
 
def analyze_and_block(external_ip, flow_key):
    if flows[flow_key]['blocked']:
        return
 
    flow = flows[flow_key]
    total_packets = flow['fwd_pkts'] + flow['bwd_pkts']
    flow_duration = float(flow['last_pkt_time']) - float(flow['start_time'])
    if flow_duration <= 0: flow_duration = 0.001
 
    data = {feat: 0 for feat in required_features}
 
    try:
        # --- FEATURE CALCULATION ---
        smart_setter(data, 'Flow Duration', int(flow_duration * 1e6))
        smart_setter(data, 'Flow Bytes/s', (sum(flow['fwd_lengths']) + sum(flow['bwd_lengths'])) / flow_duration)
        smart_setter(data, 'Flow Packets/s', total_packets / flow_duration)
        smart_setter(data, 'Bwd Packets/s', flow['bwd_pkts'] / flow_duration if flow_duration > 0 else 0)
 
        if flow['fwd_lengths']:
            smart_setter(data, 'Fwd Packets Length Total', sum(flow['fwd_lengths']))
            smart_setter(data, 'Fwd Packet Length Max', np.max(flow['fwd_lengths']))
            smart_setter(data, 'Fwd Packet Length Min', np.min(flow['fwd_lengths']))
            smart_setter(data, 'Fwd Packet Length Mean', np.mean(flow['fwd_lengths']))
            smart_setter(data, 'Fwd Packet Length Std', np.std(flow['fwd_lengths']))
 
        if flow['bwd_lengths']:
            smart_setter(data, 'Bwd Packet Length Std', np.std(flow['bwd_lengths']))
 
        all_lengths = flow['fwd_lengths'] + flow['bwd_lengths']
        if all_lengths:
            smart_setter(data, 'Packet Length Min', np.min(all_lengths))
            smart_setter(data, 'Packet Length Std', np.std(all_lengths))
            smart_setter(data, 'Avg Packet Size', np.mean(all_lengths))
 
        if flow['all_iats']:
            smart_setter(data, 'Flow IAT Max', np.max(flow['all_iats']))
            smart_setter(data, 'Flow IAT Std', np.std(flow['all_iats']))
            smart_setter(data, 'Flow IAT Min', np.min(flow['all_iats']))
 
        smart_setter(data, 'Fwd IAT Total', sum(flow['fwd_iats']) if flow['fwd_iats'] else 0)
        smart_setter(data, 'Bwd IAT Total', sum(flow['bwd_iats']) if flow['bwd_iats'] else 0)
        smart_setter(data, 'Init Fwd Win Bytes', -1)
        smart_setter(data, 'Fwd Seg Size Min', 8)
 
    except Exception as e:
        print(f" [!] Feature Prep Error: {e}")
        return
 
    # --- PREDICTION ---
    try:
        attack_type = "BENIGN"
        confidence = 0.0
 
        if not heuristic_only_mode and model is not None:
            df = pd.DataFrame([data])[required_features].fillna(0)
            raw_pred = model.predict(df)[0]
            pred_confidence = model.predict_proba(df)[0]
            pred_label = str(int(raw_pred))
            attack_type = labels_dict.get(pred_label, "Unknown")
            confidence = np.max(pred_confidence)
            print(f"[*] ML Prediction: {attack_type} ({confidence:.2%})")
 
        # --- HEURISTIC OVERRIDE ---
        avg_pkt_size = data.get('Avg Packet Size', 0)
        flow_pkt_rate = data.get('Flow Packets/s', 0)
        is_amplification = (total_packets > 50 and flow_pkt_rate > 100 and avg_pkt_size > 200)
 
        if is_amplification:
            print(f"[!] HEURISTIC ALERT: DNS Amplification pattern detected!")
            attack_type = "DrDoS_DNS"
            confidence = max(confidence, 0.95)
 
        # --- LOG AND BLOCK ---
        if ("DrDoS_DNS" in attack_type) and confidence > 0.5:
            flows[flow_key]['blocked'] = True
 
            # UNIFIED DATABASE LOGGING
            log_attack_and_ban(
                source_ip=external_ip,
                attack_type=attack_type,
                target_port=53,
                protocol="UDP",
                confidence=float(confidence)
            )
 
            # Local CSV Backup
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            with open(LOG_FILE, 'a') as f:
                f.write(f"{timestamp},{external_ip},{attack_type},{total_packets},{avg_pkt_size:.2f},{flow_pkt_rate:.2f},{confidence:.4f}\n")
 
            print(f"[🚨 ALERT] DNS DDoS BLOCKED: {external_ip} | Confidence: {confidence:.2%}")
 
    except Exception as e:
        print(f"[!] Analysis error: {e}")
 
# ============================================================================
# 9. PACKET PROCESSING
# ============================================================================
 
def packet_callback(pkt):
    if IP not in pkt or UDP not in pkt: return
 
    src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
    sport, dport = pkt[UDP].sport, pkt[UDP].dport
 
    # INBOUND (External -> Pi)
    if dst_ip == MY_IP and dport == DNS_PORT:
        flow_key = src_ip
        pkt_time = float(pkt.time)
 
        if flows[flow_key]['start_time'] is None:
            flows[flow_key]['start_time'] = pkt_time
 
        prev_time = flows[flow_key]['last_pkt_time']
        if prev_time:
            flows[flow_key]['all_iats'].append((pkt_time - prev_time) * 1e6)
 
        flows[flow_key]['last_pkt_time'] = pkt_time
        flows[flow_key]['fwd_pkts'] += 1
        flows[flow_key]['fwd_lengths'].append(len(pkt))
 
        if (flows[flow_key]['fwd_pkts'] + flows[flow_key]['bwd_pkts']) >= PACKET_THRESHOLD and not flows[flow_key]['analyzed']:
            flows[flow_key]['analyzed'] = True
            analyze_and_block(src_ip, flow_key)
 
    # OUTBOUND (Pi -> External)
    elif src_ip == MY_IP and sport == DNS_PORT:
        flow_key = dst_ip
        pkt_time = float(pkt.time)
        flows[flow_key]['bwd_pkts'] += 1
        flows[flow_key]['bwd_lengths'].append(len(pkt))
 
if __name__ == "__main__":
    print("[*] Starting DNS Sentry capture...")
    try:
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[*] Sentry offline.")
