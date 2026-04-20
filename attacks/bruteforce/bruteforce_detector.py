#!/usr/bin/env python3
import os
import json
import time
import joblib
import pandas as pd
import numpy as np
import warnings
import sys
import sqlite3
from scapy.all import sniff, IP, TCP, get_if_addr, conf
from collections import defaultdict
import pytz
from datetime import datetime

# --- 1. INTEGRATE GEO UTILS ---
sys.path.append('/home/vinayak/honeypot_project')
try:
    from geo_utils import get_geo_data
except ImportError:
    print("[!] Error: geo_utils.py not found in /home/vinayak/honeypot_project/")

# 2. ASSET PATHS
BASE_PATH = '/home/vinayak/honeypot_project/models/bruteforce/'
MODEL_PATH = os.path.join(BASE_PATH, 'bruteforce_model.joblib')
SCALER_PATH = os.path.join(BASE_PATH, 'bruteforce_scaler.joblib')
FEATURES_PATH = os.path.join(BASE_PATH, 'bruteforce_features.json')
LABELS_PATH = os.path.join(BASE_PATH, 'bruteforce_labels.json')
DB_PATH = '/home/vinayak/honeypot_project/nexus_security.db'

# Whitelist: Logged for history/stats, but stays off the map and quiet in console.
WHITELIST = ["10.42.0.48", "127.0.0.1", "10.42.0.1"]

# 3. ML ASSET LOADING
model, scaler, required_features, labels_dict = None, None, [], {}
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

# 4. FLOW TRACKING
flows = defaultdict(lambda: {
    'start_time': None, 'last_pkt_time': None, 'fwd_pkts': 0, 'bwd_pkts': 0,
    'flags': [], 'last_alert_time': 0
})

PACKET_THRESHOLD = 10  # Trigger analysis every 10 packets (optimized for Hydra)
COOLDOWN = 15          # Seconds between consecutive alerts for the same IP

def analyze_and_log(src_ip, dest_port, flow_key):
    flow = flows[flow_key]
    current_time = time.time()
    
    # PERSISTENCE: Check cooldown to allow multiple attacks in one demo
    if current_time - flow['last_alert_time'] < COOLDOWN:
        return

    duration = float(flow['last_pkt_time']) - float(flow['start_time'])
    if duration <= 0: duration = 0.001

    attack_type = "Normal"
    ml_confidence = 0.0

    # --- FEATURE 1: ML PREDICTION ---
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
            ml_confidence = np.max(model.predict_proba(X_scaled)[0])
            attack_type = labels_dict.get(str(int(raw_pred)), "Normal")
        except: pass

    # --- FEATURE 2: HEURISTIC (SHARK ATTACK) ---
    psh_count = sum(1 for f in flow['flags'] if 'P' in str(f))
    is_brute = ("Brute" in attack_type or "Patator" in attack_type)
    
    if is_brute or (flow['fwd_pkts'] > 20 and psh_count > 3):
        # DYNAMIC CONFIDENCE: Blends ML with packet intensity
        final_conf = round(max(ml_confidence, min(0.70 + (psh_count * 0.05), 0.97)), 2)
        IST = pytz.timezone('Asia/Kolkata')
        timestamp = datetime.now(IST).strftime('%Y-%m-%d %H:%M:%S')
        
        # --- DYNAMIC GEO LOOKUP ---
        # returns None, None for local IPs (Heatmap ignores)
        lat, lon, country, city = get_geo_data(src_ip)
        
        # SQLITE LOGGING
        try:
            conn = sqlite3.connect(DB_PATH, timeout=30)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO attack_logs (timestamp, source_ip, attack_type, confidence, evidence, latitude, longitude, country, city)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, src_ip, "Brute Force", final_conf, 
                  f"Port {dest_port} | {flow['fwd_pkts']} pkts | {psh_count} PSH flags", lat, lon, country, city))
            conn.commit()
            conn.close()
            
            # Print alert only if NOT whitelisted to keep console clean for demo
            if src_ip not in WHITELIST:
                print(f"[🚨 ALERT] BRUTE FORCE LOGGED: {src_ip} | Conf: {final_conf:.0%}")
            
            # --- THE RESET ---
            flow['last_alert_time'] = current_time
            flow['fwd_pkts'] = 0
            flow['flags'] = []
            flow['start_time'] = None
            
        except Exception as e:
            print(f"[!] DB Error: {e}")

def packet_callback(pkt):
    if IP not in pkt or TCP not in pkt: return
    try: MY_IP = get_if_addr("wlan0")
    except: MY_IP = "10.42.0.1"

    src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
    sport, dport = pkt[TCP].sport, pkt[TCP].dport

    # Monitoring SSH (22, 2222) and FTP (21)
    if dst_ip == MY_IP and dport in [21, 22, 2222]:
        flow_key = f"{src_ip}:{dport}"
        pkt_time = float(pkt.time)
        if flows[flow_key]['start_time'] is None: flows[flow_key]['start_time'] = pkt_time
        flows[flow_key]['last_pkt_time'] = pkt_time
        flows[flow_key]['fwd_pkts'] += 1
        flows[flow_key]['flags'].append(str(pkt[TCP].flags))
        
        if flows[flow_key]['fwd_pkts'] >= PACKET_THRESHOLD:
            analyze_and_log(src_ip, dport, flow_key)

if __name__ == "__main__":
    print("[*] BruteForce Bouncer starting on wlan0 (Monitoring 21, 22, 2222)...")
    sniff(iface=["wlan0","tailscale0"], prn=packet_callback, store=False)
