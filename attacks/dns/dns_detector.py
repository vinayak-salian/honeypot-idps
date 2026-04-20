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
import sqlite3
from scapy.all import sniff, IP, UDP, get_if_addr, conf
from collections import defaultdict

# --- 1. INTEGRATE GEO UTILS ---
sys.path.append('/home/vinayak/honeypot_project')
try:
    from geo_utils import get_geo_data
except ImportError:
    print("[!] Error: geo_utils.py not found in project folder.")

# 2. CONFIGURATION & PATHS
BASE_PATH = '/home/vinayak/honeypot_project/models/dns/'
MODEL_PATH = os.path.join(BASE_PATH, 'dns_model.joblib')
SCALER_PATH = os.path.join(BASE_PATH, 'dns_scalar.joblib')
FEATURES_PATH = os.path.join(BASE_PATH, 'dns_features.json')
LABELS_PATH = os.path.join(BASE_PATH, 'dns_labels.json')
DB_PATH = '/home/vinayak/honeypot_project/nexus_security.db'
MAIN_LOG = '/home/vinayak/honeypot_project/logs/security_events.csv'

# Whitelist: Logged for history, but quiet in console and off the heatmap
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
    print("[?] DNS ML Assets Loaded.")
except Exception as e:
    print(f"[!] DNS Init Warning: {e}")

flows = defaultdict(lambda: {
    'start_time': None, 'last_pkt_time': None, 'fwd_pkts': 0, 'bwd_pkts': 0,
    'fwd_lengths': [], 'analyzed': False
})

PACKET_THRESHOLD = 1

def analyze_and_log(external_ip, flow_key):
    flow = flows[flow_key]
    duration = float(flow['last_pkt_time']) - float(flow['start_time'])
    if duration <= 0: duration = 0.001

    attack_type = "DNS_Query"
    confidence = 0.60

    # --- FEATURE 1: ML PREDICTION ---
    if model is not None:
        try:
            data = {feat: 0 for feat in required_features}
            data['Flow Duration'] = int(duration * 1e6)
            df = pd.DataFrame([data])[required_features].fillna(0)
            raw_pred = model.predict(df)[0]
            confidence = np.max(model.predict_proba(df)[0])
            attack_type = labels_dict.get(str(int(raw_pred)), "Unknown")
        except: pass

    # --- FEATURE 2: HEURISTIC (Amplification) ---
    avg_size = np.mean(flow['fwd_lengths']) if flow['fwd_lengths'] else 0
    total_packets = flow['fwd_pkts']
    if total_packets > 40 and avg_size > 200:
        attack_type = "DrDoS_DNS_Amplification"
        confidence = 0.95

    # --- LOGGING GATE ---
    if "DNS" in attack_type or "DrDoS" in attack_type or "Unknown" in attack_type:
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Get dynamic geo-location (None for local IPs = Hidden from Heatmap)
        lat, lon, country, city = get_geo_data(external_ip)

        # 1. Log to CSV (for Hostile History)
        row = [timestamp, external_ip, attack_type, 53, "UDP", round(float(confidence), 2), lat, lon, country, city]
        with open(MAIN_LOG, 'a', newline='') as f:
            csv.writer(f).writerow(row)

        # 2. Log to SQLite (for Dashboard Tables)
        try:
            conn = sqlite3.connect(DB_PATH, timeout=30)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO attack_logs (timestamp, source_ip, attack_type, confidence, evidence, latitude, longitude, country, city)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, external_ip, attack_type, round(float(confidence), 2), 
                  f"Avg Size: {int(avg_size)}B | Pkts: {total_packets}", lat, lon, country, city))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[!] DNS DB Error: {e}")

        # Console Alert (Only for non-whitelisted IPs)
        if external_ip not in WHITELIST:
            print(f"[🚨 ALERT] DNS ATTACK LOGGED: {external_ip} | Type: {attack_type} | Conf: {confidence:.2%}")

def packet_callback(pkt):
    if IP not in pkt or UDP not in pkt: return
    try: MY_IP = get_if_addr("wlan0")
    except: MY_IP = "10.42.0.1"
    
    src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
    
    # Target: UDP Port 53
    if dst_ip == MY_IP and pkt[UDP].dport == 53:
        flow_key = src_ip
        pkt_time = float(pkt.time)
        
        if flows[flow_key]['start_time'] is None: 
            flows[flow_key]['start_time'] = pkt_time
            
        flows[flow_key]['last_pkt_time'] = pkt_time
        flows[flow_key]['fwd_pkts'] += 1
        flows[flow_key]['fwd_lengths'].append(len(pkt))
        
        if flows[flow_key]['fwd_pkts'] >= PACKET_THRESHOLD and not flows[flow_key]['analyzed']:
            flows[flow_key]['analyzed'] = True
            analyze_and_log(src_ip, flow_key)

if __name__ == "__main__":
    print("[*] DNS Sentry starting on wlan0 (Monitoring UDP 53)...")
    sniff(iface="wlan0", prn=packet_callback, store=False)
