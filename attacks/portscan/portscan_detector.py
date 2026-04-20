#!/usr/bin/env python3
import os
import json
import time
import joblib
import pandas as pd
import numpy as np
import sqlite3
import sys 
from scapy.all import sniff, IP, TCP
from collections import defaultdict

# --- 1. INTEGRATE GEO UTILS ---
sys.path.append('/home/vinayak/honeypot_project')
try:
    from geo_utils import get_geo_data
except ImportError:
    print("[!] Error: geo_utils.py not found.")

# 2. ASSET PATHS
BASE_PATH = '/home/vinayak/honeypot_project/models/portscanning/'
MODEL_PATH = os.path.join(BASE_PATH, 'portscanning_model.joblib')
SCALER_PATH = os.path.join(BASE_PATH, 'portscanning_scaler.joblib')
FEATURES_PATH = os.path.join(BASE_PATH, 'portscanning_features.json')
LABELS_PATH = os.path.join(BASE_PATH, 'portscanning_labels.json')
DB_PATH = '/home/vinayak/honeypot_project/nexus_security.db'

# Whitelist: Stays off the map but logged in DB
WHITELIST = ["10.42.0.48", "127.0.0.1", "10.42.0.1"]

# 3. LOAD ML ASSETS (Preserving your exact logic)
model, scaler, required_features, labels_dict = None, None, [], {}
try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    with open(FEATURES_PATH, 'r') as f:
        data = json.load(f)
        required_features = data.get('features', []) if isinstance(data, dict) else data
    with open(LABELS_PATH, 'r') as f:
        data = json.load(f)
        labels_dict = {str(k): v for k, v in data.items()} if isinstance(data, dict) else data
    print("[✓] PortScan ML Assets Loaded.")
except Exception as e:
    print(f"[!] PortScan Init Warning: {e}")

flows = defaultdict(lambda: {
    'start_time': None, 
    'last_pkt_time': None, 
    'dest_ports': set(),
    'last_alert_time': 0
})

# --- DEMO OPTIMIZATION ---
PORT_THRESHOLD = 4  # Lowered slightly to catch vertical scans faster
COOLDOWN = 10  

def analyze_and_log(src_ip): 
    flow = flows[src_ip]
    current_time = time.time()

    if current_time - flow['last_alert_time'] < COOLDOWN:
        return False

    unique_ports = list(flow['dest_ports'])
    num_unique = len(unique_ports)
    
    # Safety check: If only 1 port was hit (Brute Force/Malware), EXIT NOW.
    if num_unique < 2:
        return False

    duration = float(flow['last_pkt_time']) - float(flow['start_time'])
    if duration <= 0: duration = 0.001

    # --- HEURISTICS ---
    scan_rate = num_unique / duration
    is_suspicious = (num_unique >= PORT_THRESHOLD and scan_rate > 0.5)

    # --- ML PREDICTION (Preserved) ---
    attack_type = "Normal"
    ml_confidence = 0.0
    if model is not None:
        try:
            data_dict = {feat: 0 for feat in required_features}
            data_dict[' Destination Port'] = float(unique_ports[-1])
            data_dict[' Flow Duration'] = int(duration * 1e6)
            df = pd.DataFrame([data_dict])[required_features]
            X_scaled = scaler.transform(df)
            raw_pred = model.predict(X_scaled)[0]
            ml_confidence = np.max(model.predict_proba(X_scaled)[0])
            attack_type = labels_dict.get(str(int(raw_pred)), "Normal")
        except: pass

    if (attack_type == "PortScan" and ml_confidence > 0.4) or is_suspicious:
        final_conf = round(ml_confidence, 2) if ml_confidence > 0.5 else round(min(0.75 + (num_unique * 0.02), 0.96), 2)
        
        # --- FIX: USE LOCAL TIME FOR IST SYNC ---
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

        lat, lon, country, city = get_geo_data(src_ip)

        try:
            conn = sqlite3.connect(DB_PATH, timeout=30)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO attack_logs (timestamp, source_ip, attack_type, confidence, evidence, latitude, longitude, country, city)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, src_ip, "PortScan", final_conf, 
                  f"Probed {num_unique} ports | Rate: {round(scan_rate, 2)} p/s", lat, lon, country, city))
            conn.commit()
            conn.close()
            
            if src_ip not in WHITELIST:
                print(f"[🚨 ALERT] {timestamp} | PORT SCAN: {src_ip} | Ports: {num_unique}")
            
            flow['last_alert_time'] = current_time
            flow['dest_ports'] = set()
            flow['start_time'] = None
            
        except Exception as e:
            print(f"[!] DB Error: {e}")
        return True
    return False

def packet_callback(pkt):
    if IP not in pkt or TCP not in pkt: return
    
    src_ip = pkt[IP].src
    if src_ip in ["127.0.0.1", "10.42.0.1"]: return

    pkt_time = float(pkt.time)
    if flows[src_ip]['start_time'] is None: 
        flows[src_ip]['start_time'] = pkt_time

    flows[src_ip]['last_pkt_time'] = pkt_time
    flows[src_ip]['dest_ports'].add(pkt[TCP].dport)

    if len(flows[src_ip]['dest_ports']) >= PORT_THRESHOLD:
        analyze_and_log(src_ip)

if __name__ == "__main__":
    # Explicitly monitor the local hotspot and the AWS tunnel
    print("[*] PortScan Engine LIVE: Monitoring wlan0 + tailscale0...")
    sniff(iface=["wlan0", "tailscale0"], filter="tcp", prn=packet_callback, store=False)
