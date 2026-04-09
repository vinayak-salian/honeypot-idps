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
 
# Global flow tracker
flows = defaultdict(lambda: {
    'start_time': None, 'last_pkt_time': None, 'dest_ports': set(),
    'blocked': False
})
 
# DEMO OPTIMIZATION: We want to catch the scan quickly
PORT_THRESHOLD = 2 
 
def analyze_and_block(src_ip):
    # Prevents duplicate logging for the same scan session
    if flows[src_ip]['blocked']: 
        return False
 
    flow = flows[src_ip]
    unique_ports = list(flow['dest_ports'])
    num_unique = len(unique_ports)
 
    # Calculate duration
    duration = float(flow['last_pkt_time']) - float(flow['start_time'])
    if duration <= 0: duration = 0.001
 
    # --- FEATURE 1: HEURISTICS ---
    # Trigger if they hit more than our threshold (aggressive for demo)
    is_suspicious = (num_unique >= PORT_THRESHOLD)
 
    # Calculate scan rate (ports per second)
    scan_rate = num_unique / duration
    if scan_rate > 10.0: is_suspicious = True
 
    # --- FEATURE 2: ML PREDICTION ---
    attack_type = "Normal"
    confidence = 0.0
    if model is not None:
        try:
            data_dict = {feat: 0 for feat in required_features}
            data_dict[' Destination Port'] = float(unique_ports[-1])
            data_dict[' Flow Duration'] = int(duration * 1e6)
 
            df = pd.DataFrame([data_dict])[required_features]
            X_scaled = scaler.transform(df)
            raw_pred = model.predict(X_scaled)[0]
            confidence = np.max(model.predict_proba(X_scaled)[0])
            attack_type = labels_dict.get(str(int(raw_pred)), "Normal")
        except: 
            pass
 
    # --- LOGIC GATE: FIRE IF EITHER HITS ---
    if (attack_type == "PortScan" and confidence > 0.4) or is_suspicious:
        flows[src_ip]['blocked'] = True
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
 
        # Log to SQLite (The source of truth for your dashboard)
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO attack_logs (timestamp, source_ip, attack_type, confidence, evidence, latitude, longitude, country, city)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, src_ip, "PortScan", round(confidence if confidence > 0 else 0.99, 2), 
                  f"Probed {num_unique} ports | Rate: {round(scan_rate, 2)} p/s", 19.076, 72.877, "India", "Mumbai"))
            conn.commit()
            conn.close()
            print(f"[🚨 ALERT] PORT SCAN LOGGED: {src_ip} | Ports: {num_unique}")
        except Exception as e:
            print(f"[!] Database Write Failed: {e}")
 
        return True
    return False
 
def packet_callback(pkt):
    if IP not in pkt or TCP not in pkt: return
 
    src_ip = pkt[IP].src
 
    # 1. Skip traffic from the Pi itself or the loopback
    if src_ip == "127.0.0.1" or src_ip == "10.42.0.1":
        return
 
    # 2. Track the Flow
    pkt_time = float(pkt.time)
    if flows[src_ip]['start_time'] is None: 
        flows[src_ip]['start_time'] = pkt_time
 
    flows[src_ip]['last_pkt_time'] = pkt_time
 
    # Add new port to the set
    if pkt[TCP].dport not in flows[src_ip]['dest_ports']:
        flows[src_ip]['dest_ports'].add(pkt[TCP].dport)
        # print(f"[DEBUG] {src_ip} -> Port {pkt[TCP].dport} (Total: {len(flows[src_ip]['dest_ports'])})")
 
    # 3. Trigger analysis every time a new port is discovered above threshold
    if len(flows[src_ip]['dest_ports']) >= PORT_THRESHOLD:
        analyze_and_block(src_ip)
 
if __name__ == "__main__":
    print("[*] PortScan Detector Engine starting on wlan0...")
    sniff(iface="wlan0", prn=packet_callback, store=False)
