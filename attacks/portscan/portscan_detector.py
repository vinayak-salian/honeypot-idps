#!/usr/bin/env python3
import os
import json
import time
import joblib
import pandas as pd
import numpy as np
import warnings
import csv
import sqlite3
from scapy.all import sniff, IP, TCP, get_if_addr
from collections import defaultdict
 
# 1. ASSET PATHS
BASE_PATH = '/home/vinayak/honeypot_project/models/portscanning/'
MODEL_PATH = os.path.join(BASE_PATH, 'portscanning_model.joblib')
SCALER_PATH = os.path.join(BASE_PATH, 'portscanning_scaler.joblib')
FEATURES_PATH = os.path.join(BASE_PATH, 'portscanning_features.json')
LABELS_PATH = os.path.join(BASE_PATH, 'portscanning_labels.json')
DB_PATH = '/home/vinayak/honeypot_project/nexus_security.db'
 
# 2. LOAD ML ASSETS
model, scaler, required_features, labels_dict = None, None, [], {}
try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    with open(FEATURES_PATH, 'r') as f:
        data = json.load(f)
        required_features = data.get('features', [])
    with open(LABELS_PATH, 'r') as f:
        data = json.load(f)
        labels_dict = {str(k): v for k, v in data.items()}
    print("[?] PortScan ML Assets Loaded.")
except Exception as e:
    print(f"[!] PortScan Init Warning: {e}")
 
flows = defaultdict(lambda: {
    'start_time': None, 'last_pkt_time': None, 'dest_ports': set(),
    'blocked': False
})
 
# DEMO OPTIMIZATION: Lower thresholds to make the Pi "sensitive"
PORT_THRESHOLD = 5 
 
def analyze_and_block(src_ip):
    if flows[src_ip]['blocked']: return False
 
    flow = flows[src_ip]
    unique_ports = list(flow['dest_ports'])
    num_unique = len(unique_ports)
    duration = float(flow['last_pkt_time']) - float(flow['start_time'])
    if duration <= 0: duration = 0.001
 
    # HEURISTIC: If they hit 5 ports, we're already suspicious
    # (Removed the rate check so slow scans are still caught)
    is_suspicious = (num_unique >= PORT_THRESHOLD)
 
    # ML PREDICTION
    attack_type = "Normal"
    confidence = 0.0
    if model is not None:
        try:
            # Prepare data for model
            data_dict = {feat: 0 for feat in required_features}
            data_dict[' Destination Port'] = float(unique_ports[-1])
            data_dict[' Flow Duration'] = int(duration * 1e6)
 
            df = pd.DataFrame([data_dict])[required_features]
            X_scaled = scaler.transform(df)
            raw_pred = model.predict(X_scaled)[0]
            confidence = np.max(model.predict_proba(X_scaled)[0])
            attack_type = labels_dict.get(str(int(raw_pred)), "Normal")
        except: pass
 
    # TRIGGER LOGIC
    if (attack_type == "PortScan" and confidence > 0.4) or is_suspicious:
        flows[src_ip]['blocked'] = True
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
 
        # Log to SQLite so it shows up in Dashboard
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO attack_logs (timestamp, source_ip, attack_type, confidence, evidence, latitude, longitude, country, city)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, src_ip, "PortScan", round(confidence if confidence > 0 else 0.99, 2), 
                  f"Ports probed: {num_unique}", 19.076, 72.877, "India", "Mumbai"))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"DB Log Error: {e}")
 
        print(f"[🚨 ALERT] PORT SCAN DETECTED: {src_ip} | Unique Ports: {num_unique}")
        return True
    return False
 
def packet_callback(pkt):
    if IP not in pkt or TCP not in pkt: return
 
    # Identify local gateway IP to filter out outgoing traffic
    try: MY_IP = get_if_addr("wlan0")
    except: MY_IP = "10.42.0.1"
 
    if pkt[IP].dst == MY_IP:
        src_ip = pkt[IP].src
        pkt_time = float(pkt.time)
 
        if flows[src_ip]['start_time'] is None: 
            flows[src_ip]['start_time'] = pkt_time
 
        flows[src_ip]['last_pkt_time'] = pkt_time
        flows[src_ip]['dest_ports'].add(pkt[TCP].dport)
 
        # Check every time a new port is added once we are over the threshold
        if len(flows[src_ip]['dest_ports']) >= PORT_THRESHOLD:
            analyze_and_block(src_ip)
 
if __name__ == "__main__":
    print("[*] PortScan Detector Engine starting...")
    sniff(iface="wlan0", prn=packet_callback, store=False)
