#!/usr/bin/env python3
"""
IOT SENTRY | ML-Powered Brute Force Detector for Raspberry Pi
Detects SSH/FTP Brute Force attacks using trained ML model
"""
 
import os
import json
import time
import joblib
import pandas as pd
import numpy as np
import warnings
from scapy.all import sniff, IP, TCP, get_if_addr, conf
from collections import defaultdict
from datetime import datetime
import sys
 
# 1. INTEGRATE UNIFIED DATABASE
sys.path.append('/home/vinayak/honeypot_project')
try:
    from honeypot_db import log_attack_and_ban
except ImportError:
    print("[!] WARNING: honeypot_db.py not found. Central logging will fail.")
 
# 2. SUPPRESS WARNINGS
from sklearn.exceptions import InconsistentVersionWarning
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
 
# ============================================================================
# 3. CONFIGURATION
# ============================================================================
BASE_PATH = '/home/vinayak/honeypot_project/models/bruteforce/'
MODEL_PATH = os.path.join(BASE_PATH, 'bruteforce_model.joblib')
SCALER_PATH = os.path.join(BASE_PATH, 'bruteforce_scaler.joblib')
FEATURES_PATH = os.path.join(BASE_PATH, 'bruteforce_features.json')
LABELS_PATH = os.path.join(BASE_PATH, 'bruteforce_labels.json')
LOG_FILE = '/home/vinayak/honeypot_project/logs/bruteforce_log.csv'
DEBUG_LOG = '/home/vinayak/honeypot_project/logs/bruteforce_debug.txt'
 
# Attack ports
SSH_PORT = 22
FTP_PORT = 21
 
# ============================================================================
# 4. HELPER FUNCTIONS
# ============================================================================
 
def init_log_file():
    """Create log file with headers if it doesn't exist."""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w') as f:
            f.write("Timestamp,Source_IP,Target_Port,Attack_Type,Packet_Count,Confidence\n")
        print(f"[*] Created log file: {LOG_FILE}")
 
def debug_log(message):
    """Write debug messages to a log file."""
    os.makedirs(os.path.dirname(DEBUG_LOG), exist_ok=True)
    with open(DEBUG_LOG, 'a') as f:
        f.write(f"[{datetime.now()}] {message}\n")
 
def load_features_json():
    """Load features from JSON properly."""
    with open(FEATURES_PATH, 'r') as f:
        data = json.load(f)
    if isinstance(data, dict):
        return data.get('features', [])
    return data
 
def load_labels_json():
    """Load labels from JSON properly."""
    with open(LABELS_PATH, 'r') as f:
        data = json.load(f)
    return {str(k): v for k, v in data.items()}
 
def get_port_name(port):
    """Get service name for common ports."""
    port_names = {SSH_PORT: "SSH", FTP_PORT: "FTP"}
    return port_names.get(port, f"Port {port}")
 
# ============================================================================
# 5. INITIALIZATION
# ============================================================================
 
print("\n" + "="*60)
print("    IOT SENTRY | ML-POWERED BRUTE FORCE DETECTOR")
print("="*60)
 
# Auto-detect PI Identity
try:
    MY_IP = get_if_addr(conf.iface)
    print(f"[*] Interface: {conf.iface}")
    print(f"[*] Local IP:  {MY_IP}")
except Exception as e:
    print(f"[!] Network Error: {e}")
    debug_log(f"Network Error: {e}")
    exit()
 
# Load ML Assets
try:
    print("[*] Loading ML Assets...")
 
    model = joblib.load(MODEL_PATH)
    print(f"    ✓ Model loaded from {MODEL_PATH}")
 
    scaler = joblib.load(SCALER_PATH)
    print(f"    ✓ Scaler loaded from {SCALER_PATH}")
 
    required_features = load_features_json()
    print(f"    ✓ Features loaded: {len(required_features)} features")
    debug_log(f"Features: {required_features}")
 
    labels_dict = load_labels_json()
    print(f"    ✓ Labels loaded: {list(labels_dict.values())}")
    debug_log(f"Labels mapping: {labels_dict}")
 
    init_log_file()
    print(f"    ✓ Log file ready: {LOG_FILE}")
 
    print(f"\n[+] System Online. Ready to detect brute force attacks.\n")
 
except Exception as e:
    print(f"[-] Initialization failed: {e}")
    debug_log(f"Initialization Error: {e}")
    import traceback
    traceback.print_exc()
    exit()
 
# ============================================================================
# 6. FLOW TRACKING DATA STRUCTURES
# ============================================================================
 
flows = defaultdict(lambda: {
    'start_time': None,           # Hardware timestamp of first packet
    'last_pkt_time': None,        # Hardware timestamp of last packet
    'fwd_pkts': 0,                # Packets from attacker to target
    'bwd_pkts': 0,                # Packets from target (Pi) to attacker
    'fwd_lengths': [],            # Fwd packet sizes
    'bwd_lengths': [],            # Bwd packet sizes
    'iats': [],                   # Inter-arrival times
    'flags': [],                  # TCP flags
    'blocked': False,
    'analyzed': False
})
 
PACKET_THRESHOLD = 30  # Analyze after 30 packets (fwd + bwd)
 
# ============================================================================
# 7. ANALYSIS & BLOCKING
# ============================================================================
 
def analyze_and_block(src_ip, dest_port, flow_key):
    """
    Analyze brute force flow using MACRO-FLOW TRACKING.
    Tracks extended back-and-forth communication for credential attacks.
    Uses hardware timestamps for accurate timing.
    """
 
    if flows[flow_key]['blocked']:
        return
 
    flow = flows[flow_key]
    total_packets = flow['fwd_pkts'] + flow['bwd_pkts']
 
    print(f"\n[*] Analyzing flow for {src_ip}:{dest_port} ({get_port_name(dest_port)})")
    print(f"    Total packets: {total_packets} (Fwd: {flow['fwd_pkts']}, Bwd: {flow['bwd_pkts']})")
 
    # Validate timestamps
    if flow['start_time'] is None or flow['last_pkt_time'] is None:
        print(f"    [!] No valid timestamps - skipping analysis")
        return
 
    flow_duration = float(flow['last_pkt_time']) - float(flow['start_time'])
    print(f"    Flow duration: {flow_duration:.4f}s")
 
    # Initialize feature dictionary with all features set to 0
    data = {feat: 0 for feat in required_features}
 
    # ======================================================================
    # FEATURE CALCULATION FOR BRUTE FORCE
    # ======================================================================
 
    try:
        # BASIC FLOW FEATURES
        data['Flow Duration'] = int(flow_duration * 1e6)  # Convert to microseconds
        data['Total Fwd Packets'] = flow['fwd_pkts']
        data['Total Backward Packets'] = flow['bwd_pkts']
 
        # PACKET LENGTH FEATURES (Forward)
        if flow['fwd_lengths']:
            data['Total Length of Fwd Packets'] = sum(flow['fwd_lengths'])
            data['Fwd Packet Length Max'] = np.max(flow['fwd_lengths'])
            data['Fwd Packet Length Min'] = np.min(flow['fwd_lengths'])
            data['Fwd Packet Length Mean'] = np.mean(flow['fwd_lengths'])
            data['Fwd Packet Length Std'] = np.std(flow['fwd_lengths'])
        else:
            data['Total Length of Fwd Packets'] = 0
            data['Fwd Packet Length Max'] = 0
            data['Fwd Packet Length Min'] = 0
            data['Fwd Packet Length Mean'] = 0
            data['Fwd Packet Length Std'] = 0
 
        # PACKET LENGTH FEATURES (Backward)
        if flow['bwd_lengths']:
            data['Total Length of Bwd Packets'] = sum(flow['bwd_lengths'])
            data['Bwd Packet Length Max'] = np.max(flow['bwd_lengths'])
            data['Bwd Packet Length Min'] = np.min(flow['bwd_lengths'])
            data['Bwd Packet Length Mean'] = np.mean(flow['bwd_lengths'])
            data['Bwd Packet Length Std'] = np.std(flow['bwd_lengths'])
        else:
            data['Total Length of Bwd Packets'] = 0
            data['Bwd Packet Length Max'] = 0
            data['Bwd Packet Length Min'] = 0
            data['Bwd Packet Length Mean'] = 0
            data['Bwd Packet Length Std'] = 0
 
        # RATE FEATURES
        if flow_duration > 0:
            data['Flow Bytes/s'] = (sum(flow['fwd_lengths']) + sum(flow['bwd_lengths'])) / flow_duration
            data['Flow Packets/s'] = total_packets / flow_duration
            data['Fwd Packets/s'] = flow['fwd_pkts'] / flow_duration
            data['Bwd Packets/s'] = flow['bwd_pkts'] / flow_duration
        else:
            data['Flow Bytes/s'] = 0
            data['Flow Packets/s'] = 0
            data['Fwd Packets/s'] = 0
            data['Bwd Packets/s'] = 0
 
        # IAT FEATURES (Inter-Arrival Times) - Flow Level
        if flow['iats']:
            data['Flow IAT Mean'] = np.mean(flow['iats'])
            data['Flow IAT Std'] = np.std(flow['iats'])
            data['Flow IAT Max'] = np.max(flow['iats'])
            data['Flow IAT Min'] = np.min(flow['iats'])
        else:
            data['Flow IAT Mean'] = 0
            data['Flow IAT Std'] = 0
            data['Flow IAT Max'] = 0
            data['Flow IAT Min'] = 0
 
        # TCP FLAG FEATURES
        fin_count = sum(1 for f in flow['flags'] if 'F' in str(f))
        syn_count = sum(1 for f in flow['flags'] if 'S' in str(f))
        rst_count = sum(1 for f in flow['flags'] if 'R' in str(f))
        psh_count = sum(1 for f in flow['flags'] if 'P' in str(f))
        ack_count = sum(1 for f in flow['flags'] if 'A' in str(f))
        urg_count = sum(1 for f in flow['flags'] if 'U' in str(f))
 
        data['FIN Flag Count'] = fin_count
        data['SYN Flag Count'] = syn_count
        data['RST Flag Count'] = rst_count
        data['PSH Flag Count'] = psh_count
        data['ACK Flag Count'] = ack_count
        data['URG Flag Count'] = urg_count
 
        # PACKET LENGTH STATISTICS
        all_lengths = flow['fwd_lengths'] + flow['bwd_lengths']
        if all_lengths:
            data['Min Packet Length'] = np.min(all_lengths)
            data['Max Packet Length'] = np.max(all_lengths)
            data['Packet Length Mean'] = np.mean(all_lengths)
            data['Packet Length Std'] = np.std(all_lengths)
            data['Average Packet Size'] = np.mean(all_lengths)
        else:
            data['Min Packet Length'] = 0
            data['Max Packet Length'] = 0
            data['Packet Length Mean'] = 0
            data['Packet Length Std'] = 0
            data['Average Packet Size'] = 0
 
        # DOWN/UP RATIO
        if flow['fwd_pkts'] > 0:
            data['Down/Up Ratio'] = flow['bwd_pkts'] / flow['fwd_pkts']
        else:
            data['Down/Up Ratio'] = 0
 
        # FORWARD IAT FEATURES
        if flow['iats']:
            data['Fwd IAT Total'] = sum(flow['iats'])
            data['Fwd IAT Mean'] = np.mean(flow['iats'])
            data['Fwd IAT Std'] = np.std(flow['iats'])
            data['Fwd IAT Max'] = np.max(flow['iats'])
            data['Fwd IAT Min'] = np.min(flow['iats'])
        else:
            data['Fwd IAT Total'] = 0
            data['Fwd IAT Mean'] = 0
            data['Fwd IAT Std'] = 0
            data['Fwd IAT Max'] = 0
            data['Fwd IAT Min'] = 0
 
        # BACKWARD IAT FEATURES
        if flow['iats']:
            data['Bwd IAT Total'] = sum(flow['iats'])
            data['Bwd IAT Mean'] = np.mean(flow['iats'])
            data['Bwd IAT Std'] = np.std(flow['iats'])
            data['Bwd IAT Max'] = np.max(flow['iats'])
            data['Bwd IAT Min'] = np.min(flow['iats'])
        else:
            data['Bwd IAT Total'] = 0
            data['Bwd IAT Mean'] = 0
            data['Bwd IAT Std'] = 0
            data['Bwd IAT Max'] = 0
            data['Bwd IAT Min'] = 0
 
        # ACTIVITY STATISTICS
        data['act_data_pkt_fwd'] = flow['fwd_pkts']
        data['min_seg_size_forward'] = np.min(flow['fwd_lengths']) if flow['fwd_lengths'] else 0
        data['Active Mean'] = flow_duration / max(1, len(flow['iats']))
        data['Active Std'] = np.std(flow['iats']) if flow['iats'] else 0
        data['Active Max'] = np.max(flow['iats']) if flow['iats'] else 0
        data['Active Min'] = np.min(flow['iats']) if flow['iats'] else 0
        data['Idle Mean'] = 0
        data['Idle Std'] = 0
        data['Idle Max'] = 0
        data['Idle Min'] = 0
 
        print(f"    [✓] Brute force features prepared (55 features)")
        print(f"        - Fwd Pkts/s: {data.get('Fwd Packets/s', 0):.2f}")
        print(f"        - Bwd Pkts/s: {data.get('Bwd Packets/s', 0):.2f}")
        print(f"        - PSH Flags: {psh_count} (credential sends)")
        print(f"        - SYN: {syn_count}, ACK: {ack_count}, RST: {rst_count}")
 
    except Exception as e:
        print(f"    [!] Error preparing brute force features: {e}")
        debug_log(f"Feature preparation error for {flow_key}: {e}")
        import traceback
        traceback.print_exc()
        return
 
    # ======================================================================
    # MAKE PREDICTION using brute force data
    # ======================================================================
 
    try:
        df = pd.DataFrame([data])[required_features]
        X_scaled = scaler.transform(df)
        X_scaled_df = pd.DataFrame(X_scaled, columns=required_features)
 
        raw_pred = model.predict(X_scaled_df)[0]
        pred_confidence = model.predict_proba(X_scaled_df)[0]
 
        # Convert prediction to string key
        pred_label = str(int(raw_pred))
        attack_type = labels_dict.get(pred_label, "Unknown")
        confidence = np.max(pred_confidence)
 
        print(f"\n[*] ML Prediction: Class={pred_label} ({attack_type}) | Confidence: {confidence:.2%}")
        if len(pred_confidence) > 1:
            for i, label in enumerate(labels_dict.values()):
                print(f"    {label}={pred_confidence[i]:.2%}" if i < len(pred_confidence) else "")
        debug_log(f"Prediction for {flow_key}: Class={pred_label} ({attack_type}) | Confidence: {confidence}")
 
        # ====================================================================
        # HEURISTIC FALLBACK: Defense in Depth
        # ====================================================================
        flow_packets_per_sec = total_packets / flow_duration if flow_duration > 0 else 0
        is_suspicious = (
            total_packets > 25 and
            dest_port in [SSH_PORT, FTP_PORT] and
            psh_count > 3 and
            flow_packets_per_sec > 1.0
        )
 
        if is_suspicious:
            print(f"\n[!] HEURISTIC ALERT: Brute force attack pattern detected!")
            print(f"    Target: {get_port_name(dest_port)}")
            print(f"    Extended communication: {total_packets} packets")
            print(f"    Credential sends: {psh_count} PSH flags")
            print(f"    Activity rate: {flow_packets_per_sec:.2f} pkt/s")
            attack_type = "Brute-Force"
            confidence = 0.95
 
        # ====================================================================
        # BLOCK IF BRUTE FORCE DETECTED
        # ====================================================================
        if ("SSH-Patator" in attack_type or "FTP-Patator" in attack_type or 
            "Brute-Force" in attack_type) and confidence > 0.5:
            flows[flow_key]['blocked'] = True
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
 
            print(f"\n[🚨 ALERT] BRUTE FORCE ATTACK DETECTED!")
            print(f"    Source IP: {src_ip}")
            print(f"    Target Port: {dest_port} ({get_port_name(dest_port)})")
            print(f"    Attack Type: {attack_type}")
            print(f"    Total Packets: {total_packets}")
 
            # Safe calculation to avoid terminal line-wrap bugs
            det_method = 'ML Model' if confidence > 0.5 and not is_suspicious else 'Heuristic'
            print(f"    Detection Method: {det_method}")
            print(f"    Confidence: {confidence:.2%}")
 
            # 1. UNIFIED DATABASE LOGGING
            try:
                log_attack_and_ban(
                    source_ip=src_ip, 
                    attack_type=attack_type, 
                    target_port=dest_port, 
                    protocol="TCP", 
                    confidence=float(confidence)
                )
            except Exception as e:
                print(f"[!] Unified Logging Failed: {e}")
 
            # 2. Local CSV Logging
            with open(LOG_FILE, 'a') as f:
                f.write(f"{timestamp},{src_ip},{dest_port},{attack_type},{total_packets},{confidence:.4f}\n")
 
            debug_log(f"ATTACK LOGGED: {src_ip}:{dest_port} - {attack_type} - {total_packets} packets")
 
            # 3. Block the IP
            try:
                print(f"[*] Blocking IP: {src_ip}")
                # os.system(f"sudo iptables -A INPUT -s {src_ip} -j DROP") # Disabled for 12-hour safe run
                print(f"[+] IP block logged (iptables disabled for safe run)")
            except Exception as e:
                print(f"[!] Could not block IP (may need sudo): {e}")
                debug_log(f"Blocking error for {src_ip}: {e}")
        else:
            print(f"\n[*] Benign communication detected: {attack_type}")
 
    except Exception as e:
        print(f"\n[!] Prediction error: {e}")
        debug_log(f"Prediction error for {flow_key}: {e}")
        import traceback
        traceback.print_exc()
 
# ============================================================================
# 8. PACKET PROCESSING
# ============================================================================
 
def packet_callback(pkt):
    """
    Process incoming packets using HARDWARE TIMESTAMPS.
    Track bidirectional communication strictly for SSH/FTP.
    Correctly identifies responses by checking sport (source port).
    """
    if IP not in pkt or TCP not in pkt:
        return
 
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
 
    # Identify ports regardless of direction
    dport = pkt[TCP].dport
    sport = pkt[TCP].sport
 
    # ======================================================================
    # INBOUND TRAFFIC (Attacker -> Pi)
    # ======================================================================
    if dst_ip == MY_IP and dport in [SSH_PORT, FTP_PORT]:
        flow_key = f"{src_ip}:{dport}"
        pkt_time = float(pkt.time)
 
        # Initialize flow if first packet
        if flows[flow_key]['start_time'] is None:
            flows[flow_key]['start_time'] = pkt_time
            flows[flow_key]['last_pkt_time'] = pkt_time
 
        # Calculate inter-arrival time
        prev_time = flows[flow_key]['last_pkt_time']
        if prev_time is not None:
            flows[flow_key]['iats'].append((pkt_time - prev_time) * 1e6)
 
        # Update last packet timestamp
        flows[flow_key]['last_pkt_time'] = pkt_time
 
        # Record forward (attacker -> Pi) packet
        flows[flow_key]['fwd_pkts'] += 1
        flows[flow_key]['fwd_lengths'].append(len(pkt))
        flows[flow_key]['flags'].append(str(pkt[TCP].flags))
 
        # Trigger analysis continuously every 30 packets
        total_packets = flows[flow_key]['fwd_pkts'] + flows[flow_key]['bwd_pkts']
        if total_packets > 0 and total_packets % PACKET_THRESHOLD == 0:
            analyze_and_block(src_ip, dport, flow_key)
 
    # ======================================================================
    # OUTBOUND TRAFFIC (Pi -> Attacker)
    # ======================================================================
    elif src_ip == MY_IP and sport in [SSH_PORT, FTP_PORT]:
        # The Pi is responding FROM port 22/21 to the attacker
        flow_key = f"{dst_ip}:{sport}"
        pkt_time = float(pkt.time)
 
        # If Pi responds before we caught the inbound packet (rare but possible)
        if flows[flow_key]['start_time'] is None:
            flows[flow_key]['start_time'] = pkt_time
            flows[flow_key]['last_pkt_time'] = pkt_time
 
        # Update last packet timestamp
        flows[flow_key]['last_pkt_time'] = pkt_time
 
        # Record backward (Pi -> attacker) packet
        flows[flow_key]['bwd_pkts'] += 1
        flows[flow_key]['bwd_lengths'].append(len(pkt))
        flows[flow_key]['flags'].append(str(pkt[TCP].flags))
 
        # Trigger analysis continuously every 30 packets
        total_packets = flows[flow_key]['fwd_pkts'] + flows[flow_key]['bwd_pkts']
        if total_packets > 0 and total_packets % PACKET_THRESHOLD == 0:
            analyze_and_block(dst_ip, sport, flow_key)
 
# ============================================================================
# 9. START SNIFFING
# ============================================================================
 
if __name__ == "__main__":
    print("[*] Starting packet capture in Standalone Mode...")
    print("[*] Listening for attack patterns...\n")
 
    try:
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n\n[*] Sentry shutdown requested")
        print("[*] Generating final report...")
 
        if flows:
            print(f"\n[REPORT] Analyzed {len(flows)} unique flows")
            attack_count = sum(1 for f in flows.values() if f['blocked'])
            print(f"[REPORT] Attacks detected and blocked: {attack_count}")
 
        print("[*] Sentry offline. Stay safe!\n")
    except Exception as e:
        print(f"\n[!] Critical error: {e}")
