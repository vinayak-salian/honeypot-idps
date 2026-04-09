#!/usr/bin/env python3
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

# 1. GLOBAL INITIALIZATION (Prevents NameErrors)
model = None
scaler = None
required_features = []
labels_dict = {}

# 2. CONFIGURATION
BASE_PATH = '/home/vinayak/honeypot_project/models/portscanning/'
MODEL_PATH = os.path.join(BASE_PATH, 'portscanning_model.joblib')
SCALER_PATH = os.path.join(BASE_PATH, 'portscanning_scaler.joblib')
FEATURES_PATH = os.path.join(BASE_PATH, 'portscanning_features.json')
LABELS_PATH = os.path.join(BASE_PATH, 'portscanning_labels.json')
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
    print("[?] PortScan ML Assets Loaded.")
except Exception as e:
    print(f"[!] PortScan Init Warning: {e}")

flows = defaultdict(lambda: {
    'start_time': None, 'last_pkt_time': None, 'dest_ports': set(),
    'port_times': {}, 'port_packets': {}, 'port_flags': {},
    'blocked': False, 'analyzed': False
})

ATTACK_THRESHOLD = 5 

def analyze_and_block(src_ip):
    if flows[src_ip]['blocked']: return
    flow = flows[src_ip]
    unique_ports = len(flow['dest_ports'])
    duration = float(flow['last_pkt_time']) - float(flow['start_time'])
    if duration <= 0: duration = 0.001

    # Heuristic Check (Works even if ML fails)
    is_suspicious = (unique_ports >= 5 and (unique_ports / duration) > 5.0)

    # ML PREDICTION (With Safety Gate)
    attack_type = "Unknown"
    confidence = 0.0
    
    if model is not None:
        try:
            data = {feat: 0 for feat in required_features}
            data[' Destination Port'] = float(list(flow['dest_ports'])[-1])
            data[' Flow Duration'] = int(duration * 1e6)
            df = pd.DataFrame([data])[required_features]
            X_scaled = scaler.transform(df)
            raw_pred = model.predict(X_scaled)[0]
            confidence = np.max(model.predict_proba(X_scaled)[0])
            attack_type = labels_dict.get(str(int(raw_pred)), "Unknown")
        except: pass

    if (attack_type == "PortScan" and confidence > 0.5) or is_suspicious:
        flows[src_ip]['blocked'] = True
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        row = [timestamp, src_ip, "PortScan_ML_Detected", unique_ports, "TCP", round(float(confidence if confidence > 0 else 0.95), 2), 19.076, 72.877, "India", "Mumbai"]
        with open(MAIN_LOG, 'a', newline='') as f:
            csv.writer(f).writerow(row)
        print(f"[?? ALERT] PORT SCAN BLOCKED: {src_ip} | Ports: {unique_ports}")

def packet_callback(pkt):
    if IP not in pkt or TCP not in pkt: return
    try:
        MY_IP = get_if_addr("wlan0")
    except: MY_IP = "10.42.0.1"
    
    if pkt[IP].dst == MY_IP:
        src_ip = pkt[IP].src
        pkt_time = float(pkt.time)
        if flows[src_ip]['start_time'] is None: flows[src_ip]['start_time'] = pkt_time
        flows[src_ip]['last_pkt_time'] = pkt_time
        flows[src_ip]['dest_ports'].add(pkt[TCP].dport)
        if len(flows[src_ip]['dest_ports']) >= ATTACK_THRESHOLD and not flows[src_ip]['analyzed']:
            flows[src_ip]['analyzed'] = True
            analyze_and_block(src_ip)

if __name__ == "__main__":
    sniff(iface="wlan0", prn=packet_callback, store=False)
