#!/usr/bin/env python3

"""

IOT SENTRY | ML-Powered Port Scan Detector for Raspberry Pi

Detects port scanning attacks using trained ML model

"""

 

import os

import json

import time

import joblib

import pandas as pd

import numpy as np

import warnings

from scapy.all import sniff, IP, TCP, UDP, get_if_addr, conf

from collections import defaultdict

from datetime import datetime

 

# 1. SUPPRESS WARNINGS

from sklearn.exceptions import InconsistentVersionWarning

warnings.filterwarnings("ignore", category=UserWarning)

warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

 

# ============================================================================

# 2. CONFIGURATION

# ============================================================================

BASE_PATH = '/home/vinayak/honeypot_project/models/portscanning/'

MODEL_PATH = os.path.join(BASE_PATH, 'portscanning_model.joblib')

SCALER_PATH = os.path.join(BASE_PATH, 'portscanning_scaler.joblib')

FEATURES_PATH = os.path.join(BASE_PATH, 'portscanning_features.json')

LABELS_PATH = os.path.join(BASE_PATH, 'portscanning_labels.json')

LOG_FILE = '/home/vinayak/honeypot_project/logs/portscan_log.csv'

DEBUG_LOG = '/home/vinayak/honeypot_project/logs/debug_log.txt'

 

# ============================================================================

# 3. HELPER FUNCTIONS

# ============================================================================

 

def init_log_file():

    """Create log file with headers if it doesn't exist."""

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    if not os.path.exists(LOG_FILE):

        with open(LOG_FILE, 'w') as f:

            f.write("Timestamp,Source_IP,Attack_Type,Ports_Scanned,Confidence\n")

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

    # Handle both dict and list formats

    if isinstance(data, dict):

        return data.get('features', [])

    return data

 

def load_labels_json():

    """Load labels from JSON properly."""

    with open(LABELS_PATH, 'r') as f:

        data = json.load(f)

    # Convert all keys to strings to match model output

    return {str(k): v for k, v in data.items()}

 

# ============================================================================

# 4. INITIALIZATION

# ============================================================================

 

print("\n" + "="*60)

print("     IOT SENTRY | ML-POWERED PORT SCAN DETECTOR")

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

    print(f"    âœ“ Model loaded from {MODEL_PATH}")

 

    scaler = joblib.load(SCALER_PATH)

    print(f"    âœ“ Scaler loaded from {SCALER_PATH}")

 

    required_features = load_features_json()

    print(f"    âœ“ Features loaded: {len(required_features)} features")

    debug_log(f"Features: {required_features}")

 

    labels_dict = load_labels_json()

    print(f"    âœ“ Labels loaded: {list(labels_dict.values())}")

    debug_log(f"Labels mapping: {labels_dict}")

 

    init_log_file()

    print(f"    âœ“ Log file ready: {LOG_FILE}")

 

    print(f"\n[+] System Online. Ready to detect attacks.\n")

 

except Exception as e:

    print(f"[-] Initialization failed: {e}")

    debug_log(f"Initialization Error: {e}")

    import traceback

    traceback.print_exc()

    exit()

 

# ============================================================================

# 5. FLOW TRACKING DATA STRUCTURES

# ============================================================================

 

flows = defaultdict(lambda: {

    'start_time': None,          # Hardware timestamp of first packet

    'last_pkt_time': None,       # Hardware timestamp of last packet

    'dest_ports': set(),         # Unique ports contacted

    'port_times': {},            # {port: [arrival_times]} for each port

    'port_packets': {},          # {port: [packet_sizes]} for each port

    'port_flags': {},            # {port: [tcp_flags]} for each port

    'blocked': False,

    'analyzed': False

})

 

ATTACK_THRESHOLD = 5  # Analyze after detecting 5 unique ports (micro-flow friendly)

 

# ============================================================================

# 6. ANALYSIS & BLOCKING

# ============================================================================

 

def analyze_and_block(src_ip):

    """

    Analyze port scan flow using MICRO-FLOW SIMULATION.

    Treats each port scan probe as a separate micro-flow with 1 packet.

    Uses hardware timestamps for accurate timing.

    """

 

    if flows[src_ip]['blocked']:

        return

 

    flow = flows[src_ip]

    unique_ports = len(flow['dest_ports'])

 

    print(f"\n[*] Analyzing flow from {src_ip}")

    print(f"    Unique ports contacted: {sorted(flow['dest_ports'])}")

    print(f"    Total ports: {unique_ports}")

 

    # Calculate total flow duration using hardware timestamps

    if flow['start_time'] is None or flow['last_pkt_time'] is None:

        print(f"    [!] No valid timestamps - skipping analysis")

        return

 

    total_duration = float(flow['last_pkt_time']) - float(flow['start_time'])

    print(f"    Total hardware duration: {total_duration:.4f}s")

 

    # MICRO-FLOW SIMULATION: Average duration per port

    avg_micro_duration = total_duration / unique_ports if unique_ports > 0 else 0.001

    print(f"    Avg micro-flow duration per port: {avg_micro_duration:.6f}s")

 

    # Initialize feature dictionary with all 78 features set to 0

    data = {feat: 0 for feat in required_features}

 

    # ======================================================================

    # MICRO-FLOW FEATURE CALCULATION

    # ======================================================================

 

    try:

        # Get the most recent port (last probe)

        recent_port = sorted(flow['dest_ports'])[-1] if flow['dest_ports'] else 0

 

        # Collect all IAT values across all ports

        all_iats = []

        all_lengths = []

        all_flags = []

 

        for port in sorted(flow['dest_ports']):

            if port in flow['port_times'] and len(flow['port_times'][port]) > 1:

                # Calculate IATs for this port's packets

                times = sorted(flow['port_times'][port])

                for i in range(1, len(times)):

                    iat_us = (times[i] - times[i-1]) * 1e6  # Convert to microseconds

                    all_iats.append(iat_us)

 

            # Collect packet sizes for this port

            if port in flow['port_packets']:

                all_lengths.extend(flow['port_packets'][port])

 

            # Collect flags for this port

            if port in flow['port_flags']:

                all_flags.extend(flow['port_flags'][port])

 

        # ====================================================================

        # MICRO-FLOW SIM: Hardcode packet counts for stealth scan

        # ====================================================================

        data[' Total Fwd Packets'] = 1          # Simulate single probe per port

        data[' Total Backward Packets'] = 0     # No responses (typical SYN scan)

 

        # ====================================================================

        # DESTINATION PORT: Use actual port, NOT count

        # ====================================================================

        data[' Destination Port'] = float(recent_port)

 

        # ====================================================================

        # FLOW DURATION: Use actual hardware duration

        # ====================================================================

        data[' Flow Duration'] = int(total_duration * 1e6)  # Convert to microseconds

 

        # ====================================================================

        # IAT FEATURES: Inter-Arrival Times

        # ====================================================================

        if all_iats:

            data[' Flow IAT Mean'] = np.mean(all_iats)

            data[' Flow IAT Max'] = np.max(all_iats)

            data[' Flow IAT Min'] = np.min(all_iats)

            data[' Flow IAT Std'] = np.std(all_iats)

        else:

            # Single port or no inter-arrival times - set reasonable defaults

            data[' Flow IAT Mean'] = 0

            data[' Flow IAT Max'] = 0

            data[' Flow IAT Min'] = 0

            data[' Flow IAT Std'] = 0

 

        # ====================================================================

        # PACKET LENGTH FEATURES

        # ====================================================================

        if all_lengths:

            data['Total Length of Fwd Packets'] = sum(all_lengths)

            data[' Fwd Packet Length Max'] = np.max(all_lengths)

            data[' Fwd Packet Length Min'] = np.min(all_lengths)

            data[' Fwd Packet Length Mean'] = np.mean(all_lengths)

            data[' Fwd Packet Length Std'] = np.std(all_lengths)

        else:

            # No packets - set to 0

            data['Total Length of Fwd Packets'] = 0

            data[' Fwd Packet Length Max'] = 0

            data[' Fwd Packet Length Min'] = 0

            data[' Fwd Packet Length Mean'] = 0

            data[' Fwd Packet Length Std'] = 0

 

        data[' Total Length of Bwd Packets'] = 0  # No responses

 

        # ====================================================================

        # RATE FEATURES: Use micro-flow simulation duration

        # ====================================================================

        if avg_micro_duration > 0:

            # Rate features based on stealth scan (1 packet per micro-flow)

            data[' Flow Packets/s'] = 1.0 / avg_micro_duration

            data[' Flow Bytes/s'] = (data[' Fwd Packet Length Mean'] / avg_micro_duration) if data[' Fwd Packet Length Mean'] > 0 else 0

            data['Fwd Packets/s'] = 1.0 / avg_micro_duration

        else:

            data[' Flow Packets/s'] = 0

            data[' Flow Bytes/s'] = 0

            data['Fwd Packets/s'] = 0

 

        # ====================================================================

        # FLAG FEATURES: Check for SYN flag

        # ====================================================================

        if ' SYN Flag Count' in data:

            syn_count = sum(1 for flag in all_flags if 'S' in str(flag))

            data[' SYN Flag Count'] = syn_count

 

        # ====================================================================

        # BAKCWARD PACKET FEATURES

        # ====================================================================

        if ' Bwd Packet Length Max' in data:

            data[' Bwd Packet Length Max'] = 0

        if ' Bwd Packet Length Mean' in data:

            data[' Bwd Packet Length Mean'] = 0

        if ' Bwd Packet Length Min' in data:

            data[' Bwd Packet Length Min'] = 0

 

        print(f"    [âœ“] Micro-flow features prepared")

        print(f"        - Avg micro duration: {avg_micro_duration:.6f}s")

        print(f"        - Fwd Packets/s: {data['Fwd Packets/s']:.2f}")

        print(f"        - SYN Flags: {data.get(' SYN Flag Count', 0):.0f}")

        print(f"        - Port (most recent): {recent_port}")

 

    except Exception as e:

        print(f"    [!] Error preparing micro-flow features: {e}")

        debug_log(f"Feature preparation error for {src_ip}: {e}")

        import traceback

        traceback.print_exc()

        return

 

    # ======================================================================

    # MAKE PREDICTION using micro-flow data

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

            print(f"    BENIGN={pred_confidence[0]:.2%}, PortScan={pred_confidence[1]:.2%}")

        debug_log(f"Prediction for {src_ip}: Class={pred_label} ({attack_type}) | Confidence: {confidence}")

 

        # ====================================================================

        # HEURISTIC FALLBACK: Micro-flow heuristics

        # ====================================================================

        # Rule 1: Fast aggressive scanning

        is_fast_scan = (

            unique_ports >= 5 and                      # Multiple ports

            data[' Flow Packets/s'] > 5.0 and          # Fast rate (lowered from 10)

            data[' Fwd Packet Length Mean'] < 100      # Small packets (SYN probes)

        )

 

        # Rule 2: Slow stealthy scanning (multiple ports with small packets, slow rate)

        is_slow_stealth_scan = (

            unique_ports >= 5 and                      # Multiple ports

            data[' Fwd Packet Length Mean'] < 100 and  # Small packets (SYN probes)

            data[' SYN Flag Count'] >= 3               # Multiple SYN flags

        )

 

        is_suspicious = is_fast_scan or is_slow_stealth_scan

 

        if is_suspicious:

            scan_type = "Fast Aggressive" if is_fast_scan else "Slow Stealth"

            print(f"\n[!] HEURISTIC ALERT: {scan_type} scanning behavior detected!")

            print(f"    Unique Ports: {unique_ports}")

            print(f"    Scan Rate: {data[' Flow Packets/s']:.2f} pkt/s")

            print(f"    Avg Packet Size: {data[' Fwd Packet Length Mean']:.1f} bytes")

            print(f"    SYN Flags: {data.get(' SYN Flag Count', 0):.0f}")

            attack_type = "PortScan"

            confidence = 0.95

 

        # ====================================================================

        # BLOCK IF PORT SCAN DETECTED

        # ====================================================================

        if (attack_type == "PortScan" and confidence > 0.5) or is_suspicious:

            flows[src_ip]['blocked'] = True

            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

 

            print(f"\n[ðŸš¨ ALERT] PORT SCAN DETECTED!")

            print(f"    Source IP: {src_ip}")

            print(f"    Unique Ports Scanned: {unique_ports}")

            print(f"    Detection Method: {'ML Model' if confidence > 0.5 else 'Heuristic'}")

            print(f"    Confidence: {confidence:.2%}")

 

            # Log the attack

            with open(LOG_FILE, 'a') as f:

                f.write(f"{timestamp},{src_ip},{attack_type},{unique_ports},{confidence:.4f}\n")

 

            debug_log(f"ATTACK LOGGED: {src_ip} - {attack_type} - {unique_ports} ports")

 

            # Block the IP (requires sudo)

            try:

                print(f"[*] Blocking IP: {src_ip}")

                os.system(f"sudo iptables -A INPUT -s {src_ip} -j DROP")

                print(f"[+] IP blocked successfully")

            except Exception as e:

                print(f"[!] Could not block IP (may need sudo): {e}")

                debug_log(f"Blocking error for {src_ip}: {e}")

        else:

            print(f"\n[*] Benign micro-flow detected: {attack_type}")

 

    except Exception as e:

        print(f"\n[!] Prediction error: {e}")

        debug_log(f"Prediction error for {src_ip}: {e}")

        import traceback

        traceback.print_exc()

 

# ============================================================================

# 7. PACKET PROCESSING

# ============================================================================

 

def packet_callback(pkt):

    """

    Process incoming packets using HARDWARE TIMESTAMPS.

    Track arrival times per port for accurate micro-flow simulation.

    """

 

    if IP not in pkt or TCP not in pkt:

        return

 

    src_ip = pkt[IP].src

    dst_ip = pkt[IP].dst

 

    # INBOUND TRAFFIC (to our Pi) - ONLY TCP packets

    if dst_ip == MY_IP:

        # ====================================================================

        # HARDWARE TIMESTAMP: Use packet's actual arrival time, not Python time

        # ====================================================================

        pkt_arrival_time = float(pkt.time)

        dest_port = pkt[TCP].dport

        pkt_size = len(pkt)

        tcp_flags = str(pkt[TCP].flags)

 

        # Initialize flow if first packet from this source

        if flows[src_ip]['start_time'] is None:

            flows[src_ip]['start_time'] = pkt_arrival_time

            flows[src_ip]['last_pkt_time'] = pkt_arrival_time

 

        # Update last packet timestamp

        flows[src_ip]['last_pkt_time'] = pkt_arrival_time

 

        # Track this port if new

        if dest_port not in flows[src_ip]['dest_ports']:

            flows[src_ip]['dest_ports'].add(dest_port)

            flows[src_ip]['port_times'][dest_port] = []

            flows[src_ip]['port_packets'][dest_port] = []

            flows[src_ip]['port_flags'][dest_port] = []

 

        # Record packet info per port

        flows[src_ip]['port_times'][dest_port].append(pkt_arrival_time)

        flows[src_ip]['port_packets'][dest_port].append(pkt_size)

        flows[src_ip]['port_flags'][dest_port].append(tcp_flags)

 

        # Check if we've crossed the threshold for analysis

        port_count = len(flows[src_ip]['dest_ports'])

        if port_count >= ATTACK_THRESHOLD and not flows[src_ip]['analyzed']:

            flows[src_ip]['analyzed'] = True

            analyze_and_block(src_ip)

 

# ============================================================================

# 8. START SNIFFING

# ============================================================================



# Add this 'if' statement!

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

            # print(f"[REPORT] Total unique devices encountered: {len(seen_devices)}")



        print("[*] Sentry offline. Stay safe!\n")

    except Exception as e:

        print(f"\n[!] Critical error: {e}")
