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
import math
from scapy.all import sniff, IP, UDP, DNS, get_if_addr, conf
from collections import defaultdict

# --- 1. INTEGRATE GEO UTILS ---
sys.path.append('/home/vinayak/honeypot_project')
try:
    from geo_utils import get_geo_data
except ImportError:
    print("[!] Error: geo_utils.py not found.")

# 2. CONFIGURATION & PATHS
BASE_PATH = '/home/vinayak/honeypot_project/models/dns/'
MODEL_PATH = os.path.join(BASE_PATH, 'dns_model.joblib')
SCALER_PATH = os.path.join(BASE_PATH, 'dns_scalar.joblib')
FEATURES_PATH = os.path.join(BASE_PATH, 'dns_features.json')
LABELS_PATH = os.path.join(BASE_PATH, 'dns_labels.json')
DB_PATH = '/home/vinayak/honeypot_project/nexus_security.db'
MAIN_LOG = '/home/vinayak/honeypot_project/logs/security_events.csv'

# Whitelist: Your laptop is removed so we can see the alert during demo
WHITELIST = ["127.0.0.1"]

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

# --- 4. TUNNELING & FLOW STATE ---
flows = defaultdict(lambda: {
    'start_time': None, 'last_pkt_time': None, 'fwd_pkts': 0, 
    'fwd_lengths': [], 'analyzed': False, 'query_count': 0
})

# Thresholds for Tunneling Detection
ENTROPY_THRESHOLD = 3.5
TUNNEL_FREQ_THRESHOLD = 20  # Alert every 20 suspicious queries

def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x)))/len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def log_attack(ip, attack_type, confidence, evidence):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    lat, lon, country, city = get_geo_data(ip)
    
    # 1. CSV Logging
    row = [timestamp, ip, attack_type, 53, "UDP", round(float(confidence), 2), lat, lon, country, city]
    with open(MAIN_LOG, 'a', newline='') as f:
        csv.writer(f).writerow(row)

    # 2. SQLite Logging
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO attack_logs (timestamp, source_ip, attack_type, confidence, evidence, latitude, longitude, country, city)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, ip, attack_type, round(float(confidence), 2), evidence, lat, lon, country, city))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] DNS DB Error: {e}")

    # 3. Console Alert
    if ip not in WHITELIST:
        print(f"[🚨 ALERT] {attack_type} DETECTED: {ip} | Conf: {confidence:.2%} | {evidence[:50]}")

# --- NEW: LOGGING FOR WEB HISTORY ---
def log_web_history(ip, domain):
    try:
        # Ignore system/background noise to keep history "Accurate"
        noise = ['arpa', 'local', 'internal', 'broadcast', 'localhost']
        if any(n in domain.lower() for n in noise): return

        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        conn = sqlite3.connect(DB_PATH, timeout=30)
        cursor = conn.cursor()
        
        # Ensure the table exists
        cursor.execute('CREATE TABLE IF NOT EXISTS web_history (id INTEGER PRIMARY KEY, timestamp TEXT, source_ip TEXT, domain TEXT)')
        
        # Log the visit
        cursor.execute('INSERT INTO web_history (timestamp, source_ip, domain) VALUES (?, ?, ?)',
                       (timestamp, ip, domain))
        conn.commit()
        conn.close()
    except:
        pass

def packet_callback(pkt):
    if IP not in pkt or UDP not in pkt: return
    
    # Identify local gateway IP
    try: MY_IP = get_if_addr("wlan0")
    except: MY_IP = "10.42.0.1"
    
    src_ip, dst_ip = pkt[IP].src, pkt[IP].dst

    # Only process queries heading TO the Pi on port 53
    if dst_ip == MY_IP and pkt[UDP].dport == 53 and pkt.haslayer(DNS):
        flow = flows[src_ip]
        pkt_time = float(pkt.time)
        
        # Initialize Flow
        if flow['start_time'] is None: flow['start_time'] = pkt_time
        flow['last_pkt_time'] = pkt_time
        flow['fwd_pkts'] += 1
        flow['fwd_lengths'].append(len(pkt))

        # --- A. ML & AMPLIFICATION CHECK ---
        if flow['fwd_pkts'] >= 5 and not flow['analyzed']:
            flow['analyzed'] = True
            duration = pkt_time - flow['start_time']
            avg_size = np.mean(flow['fwd_lengths'])
            
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
            
            if flow['fwd_pkts'] > 40 and avg_size > 200:
                attack_type = "DrDoS_DNS_Amplification"
                confidence = 0.95
            
            if attack_type != "DNS_Query":
                log_attack(src_ip, attack_type, confidence, f"Avg Size: {int(avg_size)}B")

        # --- B. TUNNELING CHECK & WEB HISTORY ---
        try:
            if pkt[DNS].qr == 0: # 0 means it's a QUERY
                query_name = pkt[DNS].qd.qname.decode().strip('.')
                subdomain = query_name.split('.')[0]
                entropy = calculate_entropy(subdomain)

                # 1. Tunneling Detection (High Entropy)
                if entropy > ENTROPY_THRESHOLD:
                    flow['query_count'] += 1
                    if flow['query_count'] >= TUNNEL_FREQ_THRESHOLD or entropy > 4.5:
                        log_attack(src_ip, "DNS_Tunneling", 0.92, f"Entropy: {entropy:.2f} | Query: {query_name}")
                        flow['query_count'] = 0 
                
                # 2. Web History Logging (Low Entropy / Normal Sites)
                else:
                    log_web_history(src_ip, query_name)
                    
        except:
            pass

if __name__ == "__main__":
    print("[*] DNS Sentry starting on wlan0 (Monitoring UDP 53 + Tunneling + Web History)...")
    sniff(iface="wlan0", prn=packet_callback, store=False, filter="udp port 53")
