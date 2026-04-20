#!/usr/bin/env python3
"""
IOT SENTRY | MASTER ORCHESTRATOR & DISPATCHER
Version 4.9: Integrated GCM Filter (Port 5228) for Mobile Stability.
"""
import requests
import sys
import time
import threading
import sqlite3
import warnings
import json
import subprocess
import os
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, DNS, DNSQR

# Suppress warnings
warnings.filterwarnings("ignore", category=UserWarning)

# Connect to the Unified Database
sys.path.append('/home/vinayak/honeypot_project')
from honeypot_db import DB_PATH

print("\n" + "="*60)
print("    NEXUS SENTRY | MASTER ORCHESTRATOR INITIALIZING")
print("="*60)

# ============================================================================
# 1. LOAD CONFIGURATION
# ============================================================================
CONFIG_PATH = '/home/vinayak/honeypot_project/sentry_config.json'
try:
    with open(CONFIG_PATH, 'r') as f:
        config = json.load(f)
    mode = config.get("SYSTEM_MODE", "LOCAL")
    print(f"[*] Booting Sentry Core in {mode} MODE.")
    os.environ["SENTRY_MODE"] = mode
except Exception:
    print(f"[*] Defaulting to LOCAL mode.")
    os.environ["SENTRY_MODE"] = "LOCAL"

# ============================================================================
# 2. START THE MALWARE ENGINE
# ============================================================================
print("[*] Igniting Port 8080 Malware Trap...")
malware_process = None
try:
    PYTHON_BIN = "/home/vinayak/honeypot_project/venv/bin/python"
    MALWARE_SCRIPT = "/home/vinayak/honeypot_project/attacks/malware/vulnerable_server.py"
    if os.path.exists(MALWARE_SCRIPT):
        malware_process = subprocess.Popen(['sudo', PYTHON_BIN, MALWARE_SCRIPT], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[+] Malware Trap online.")
except Exception as e:
    print(f"[-] Failed to start Malware Engine: {e}")

# ============================================================================
# 3. IMPORT THE PASSIVE ML BRAINS
# ============================================================================
print("[*] Loading ML Brains into shared memory...")
try:
    from attacks.portscan.portscan_detector import packet_callback as portscan_brain
    from attacks.bruteforce.bruteforce_detector import packet_callback as bruteforce_brain
    from attacks.dns.dns_detector import packet_callback as dns_brain
    print("[+] All ML Brains successfully linked.")
except ImportError as e:
    print(f"\n[!] Failed to import ML brains: {e}")
    if malware_process: malware_process.terminate()
    sys.exit(1)

# ============================================================================
# 4. GLOBAL TRACKERS
# ============================================================================
locally_cached_bans = set()
traffic_stats = {"tcp": 0, "udp": 0, "icmp": 0, "bytes": 0}

# ============================================================================
# 5. HEARTBEATS
# ============================================================================
def traffic_heartbeat():
    while True:
        time.sleep(5)
        try:
            conn = sqlite3.connect(DB_PATH, timeout=30)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO traffic_metrics (tcp_count, udp_count, icmp_count, total_bytes) VALUES (?, ?, ?, ?)', 
                           (traffic_stats["tcp"], traffic_stats["udp"], traffic_stats["icmp"], traffic_stats["bytes"]))
            conn.commit()
            conn.close()
            for key in ["tcp", "udp", "icmp", "bytes"]: traffic_stats[key] = 0
        except: pass

def c2_polling_heartbeat():
    """Syncs local ban cache with DB every 10 seconds for the Bouncer."""
    while True:
        time.sleep(10)
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT ip FROM banned_ips")
            rows = cursor.fetchall()
            locally_cached_bans.clear()
            for row in rows: locally_cached_bans.add(row[0])
            conn.close()
        except: pass

# ============================================================================
# 6. THE DISPATCHER
# ============================================================================
def master_dispatcher(pkt):
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport
        # SILENCE: Ignore the Pi (10.42.0.1) and common noisy ports
        if src_ip == "10.42.0.1" or dst_port in [53, 5228]:
            return
        
        if src_ip.startswith("10.42.0") and dst_port not in [80, 443]:
            print(f"[DEBUG] LOCAL TRAFFIC: {src_ip} -> Port {dst_port}")

    if IP not in pkt: return

    src_ip = pkt[IP].src
    src_mac = pkt[Ether].src if Ether in pkt else "Unknown"

    # --- A. WEB BROWSING HISTORY (DNS SNIFFING) ---
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        try:
            query_domain = pkt.getlayer(DNSQR).qname.decode('utf-8').rstrip('.')
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO web_history (timestamp, source_ip, domain) VALUES (?, ?, ?)', 
                           (time.strftime('%Y-%m-%d %H:%M:%S'), src_ip, query_domain))
            conn.commit()
            conn.close()
        except: pass

    # --- B. DEVICE DISCOVERY ---
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO known_devices (mac_address, ip_address, last_seen)
            VALUES (?, ?, ?)
            ON CONFLICT(mac_address) DO UPDATE SET ip_address=excluded.ip_address, last_seen=excluded.last_seen
        ''', (src_mac, src_ip, time.strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        conn.close()
    except: pass

    # --- C. THE BOUNCER ---
    if src_ip in locally_cached_bans: return 

    # --- D. TRAFFIC TALLY & ML ROUTING ---
    traffic_stats["bytes"] += len(pkt)
    if TCP in pkt:
        traffic_stats["tcp"] += 1
        portscan_brain(pkt)
        if pkt[TCP].dport in [22, 21, 2222]: bruteforce_brain(pkt)
    elif UDP in pkt:
        traffic_stats["udp"] += 1
        if pkt[UDP].dport == 53 or pkt[UDP].sport == 53: dns_brain(pkt)
    elif ICMP in pkt:
        traffic_stats["icmp"] += 1

# ============================================================================
# 7. EXECUTION
# ============================================================================
if __name__ == "__main__":
    threading.Thread(target=c2_polling_heartbeat, daemon=True).start()
    threading.Thread(target=traffic_heartbeat, daemon=True).start()

    print("\n[+] Unified Dispatcher activated. Monitoring wlan0...")
    try:
        sniff(iface="wlan0", filter="ip", prn=master_dispatcher, store=False)
    except KeyboardInterrupt:
        if malware_process: 
            print("[*] Terminating Malware Engine...")
            malware_process.terminate()
        print("\n[!] System offline. Stay safe.")
        sys.exit(0)
