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
BASE_PATH = '/home/vinayak/honeypot_project/models/dns/'
MODEL_PATH = os.path.join(BASE_PATH, 'dns_model.joblib')
SCALER_PATH = os.path.join(BASE_PATH, 'dns_scalar.joblib')
FEATURES_PATH = os.path.join(BASE_PATH, 'dns_features.json')
LABELS_PATH = os.path.join(BASE_PATH, 'dns_labels.json')
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
    print("[?] DNS ML Assets Loaded.")
except Exception as e:
    print(f"[!] DNS Init Warning: {e}")

flows = defaultdict(lambda: {
    'start_time': None, 'last_pkt_time': None, 'fwd_pkts': 0, 'bwd_pkts': 0,
    'fwd_lengths': [], 'blocked': False, 'analyzed': False
})

PACKET_THRESHOLD = 1

def analyze_and_block(external_ip, flow_key):
    if flows[flow_key]['blocked']: return
    flow = flows[flow_key]
    total_packets = flow['fwd_pkts'] + flow['bwd_pkts']
    duration = float(flow['last_pkt_time']) - float(flow['start_time'])
    if duration <= 0: duration = 0.001

    attack_type = "DNS_Query"
    confidence = 0.60

    if model is not None:
        try:
            data = {feat: 0 for feat in required_features}
            data['Flow Duration'] = int(duration * 1e6)
            df = pd.DataFrame([data])[required_features].fillna(0)
            raw_pred = model.predict(df)[0]
            confidence = np.max(model.predict_proba(df)[0])
            attack_type = labels_dict.get(str(int(raw_pred)), "Unknown")
        except: pass

    # Heuristic for Amplification
    avg_size = np.mean(flow['fwd_lengths']) if flow['fwd_lengths'] else 0
    if total_packets > 40 and avg_size > 200:
        attack_type = "DrDoS_DNS_Amplification"
        confidence = 0.95

    if "DNS" in attack_type or "DrDoS" in attack_type:
        flows[flow_key]['blocked'] = True
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        row = [timestamp, external_ip, attack_type, 53, "UDP", round(float(confidence), 2), 19.076, 72.877, "India", "Mumbai"]
        with open(MAIN_LOG, 'a', newline='') as f:
            csv.writer(f).writerow(row)
        try: log_attack_and_ban(external_ip, attack_type, 53, "UDP", float(confidence))
        except: pass
        print(f"[?? ALERT] DNS ATTACK BLOCKED: {external_ip} | Conf: {confidence:.2%}")

def packet_callback(pkt):
    if IP not in pkt or UDP not in pkt: return
    try: MY_IP = get_if_addr("wlan0")
    except: MY_IP = "10.42.0.1"
    
    src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
    if dst_ip == MY_IP and pkt[UDP].dport == 53:
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
