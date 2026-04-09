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
from scapy.all import sniff, IP, TCP, get_if_addr, conf
from collections import defaultdict
from datetime import datetime
 
# 1. GLOBAL INITIALIZATION
model = None
scaler = None
required_features = []
labels_dict = {}
 
sys.path.append('/home/vinayak/honeypot_project')
try:
    from honeypot_db import log_attack_and_ban
except: pass
 
# 2. CONFIGURATION
BASE_PATH = '/home/vinayak/honeypot_project/models/bruteforce/'
MODEL_PATH = os.path.join(BASE_PATH, 'bruteforce_model.joblib')
SCALER_PATH = os.path.join(BASE_PATH, 'bruteforce_scaler.joblib')
FEATURES_PATH = os.path.join(BASE_PATH, 'bruteforce_features.json')
LABELS_PATH = os.path.join(BASE_PATH, 'bruteforce_labels.json')
MAIN_LOG = '/home/vinayak/honeypot_project/logs/security_events.csv'
 
# 3. ML ASSET LOADING
try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    with open(FEATURES_PATH, 'r') as f:
        data = json.load(f)
        required_features = data.get('features', []) if isinstance(data, dict) else data
    with open(LABELS_PATH, 'r') as f:
        data = json.load(f)
        labels_dict = {str(k): v for k, v in data.items()}
    print("[✓] BruteForce ML Assets Loaded.")
except Exception as e:
    print(f"[!] BruteForce Init Warning: {e}")
 
flows = defaultdict(lambda: {
    'start_time': None, 'last_pkt_time': None, 'fwd_pkts': 0, 'bwd_pkts': 0,
    'fwd_lengths': [], 'bwd_lengths': [], 'flags': [], 'blocked': False, 'analyzed': False
})
 
PACKET_THRESHOLD = 30 
 
def analyze_and_block(src_ip, dest_port, flow_key):
    if flows[flow_key]['blocked']: return
    flow = flows[flow_key]
    total_packets = flow['fwd_pkts'] + flow['bwd_pkts']
    duration = float(flow['last_pkt_time']) - float(flow['start_time'])
    if duration <= 0: duration = 0.001
 
    attack_type = "Unknown"
    confidence = 0.0
 
    if model is not None:
        try:
            data = {feat: 0 for feat in required_features}
            data['Flow Duration'] = int(duration * 1e6)
            data['Total Fwd Packets'] = flow['fwd_pkts']
            if flow['flags']:
                data['PSH Flag Count'] = sum(1 for f in flow['flags'] if 'P' in str(f))
 
            df = pd.DataFrame([data])[required_features]
            X_scaled = scaler.transform(df)
            raw_pred = model.predict(X_scaled)[0]
            confidence = np.max(model.predict_proba(X_scaled)[0])
            attack_type = labels_dict.get(str(int(raw_pred)), "Unknown")
        except: pass
 
    # Heuristic Trigger
    if total_packets > 20 and sum(1 for f in flow['flags'] if 'P' in str(f)) > 3:
        attack_type = "Brute_Force_SHARK_Attack"
        confidence = max(confidence, 0.95)
 
    if ("Brute" in attack_type or "Patator" in attack_type or "SHARK" in attack_type) and confidence > 0.5:
        flows[flow_key]['blocked'] = True
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        row = [timestamp, src_ip, attack_type, dest_port, "TCP", round(float(confidence), 2), 19.076, 72.877, "India", "Mumbai"]
        with open(MAIN_LOG, 'a', newline='') as f:
            csv.writer(f).writerow(row)
        try: log_attack_and_ban(src_ip, attack_type, dest_port, "TCP", float(confidence))
        except: pass
        print(f"[🚨 ALERT] BRUTE FORCE BLOCKED: {src_ip} | Conf: {confidence:.2%}")
 
def packet_callback(pkt):
    if IP not in pkt or TCP not in pkt: return
    try: MY_IP = get_if_addr("wlan0")
    except: MY_IP = "10.42.0.1"
 
    src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
    sport, dport = pkt[TCP].sport, pkt[TCP].dport
 
    if dst_ip == MY_IP and dport in [22, 21]:
        flow_key = f"{src_ip}:{dport}"
        pkt_time = float(pkt.time)
        if flows[flow_key]['start_time'] is None: flows[flow_key]['start_time'] = pkt_time
        flows[flow_key]['last_pkt_time'] = pkt_time
        flows[flow_key]['fwd_pkts'] += 1
        flows[flow_key]['flags'].append(str(pkt[TCP].flags))
        if flows[flow_key]['fwd_pkts'] % PACKET_THRESHOLD == 0:
            analyze_and_block(src_ip, dport, flow_key)
    elif src_ip == MY_IP and sport in [22, 21]:
        flows[f"{dst_ip}:{sport}"]['bwd_pkts'] += 1
 
if __name__ == "__main__":
    sniff(iface="wlan0", prn=packet_callback, store=False)
