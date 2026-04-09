#!/usr/bin/env python3
"""
IOT SENTRY | MASTER ORCHESTRATOR & DISPATCHER
Captures all traffic, handles global Bouncer/Heartbeat, routes to ML models,
and manages the Cloud/Local mode state.
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
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Suppress warnings from scikit-learn version mismatches
warnings.filterwarnings("ignore", category=UserWarning)

# Connect to the Unified Database
sys.path.append('/home/vinayak/honeypot_project')
from honeypot_db import DB_PATH

print("\n" + "="*60)
print("    IOT SENTRY | MASTER ORCHESTRATOR INITIALIZING")
print("="*60)

# ============================================================================
# 1. LOAD CONFIGURATION (CLOUD VS LOCAL MODE)
# ============================================================================
CONFIG_PATH = '/home/vinayak/honeypot_project/sentry_config.json'
try:
    with open(CONFIG_PATH, 'r') as f:
        config = json.load(f)
    mode = config.get("SYSTEM_MODE", "LOCAL")
    print(f"[*] Booting Sentry Core in {mode} MODE.")
    
    # Set an environment variable so honeypot_db.py knows the mode without reading the file
    os.environ["SENTRY_MODE"] = mode
except Exception as e:
    print(f"[!] Warning: Could not load config. Defaulting to LOCAL mode. Error: {e}")
    os.environ["SENTRY_MODE"] = "LOCAL"

# ============================================================================
# 2. START THE MALWARE ENGINE (Subprocess)
# ============================================================================
print("[*] Igniting Port 8080 Malware Trap...")
malware_process = None
try:
    PYTHON_BIN = "/home/vinayak/honeypot_project/venv/bin/python"
    MALWARE_SCRIPT = "/home/vinayak/honeypot_project/attacks/malware/vulnerable_server.py"
    if os.path.exists(MALWARE_SCRIPT):
        malware_process = subprocess.Popen(['sudo', PYTHON_BIN, MALWARE_SCRIPT], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[+] Malware Trap online.")
    else:
        print("[-] Malware script not found.")
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
    print("    Ensure your file paths are correct.")
    if malware_process: malware_process.terminate()
    sys.exit(1)

# ============================================================================
# 4. GLOBAL TRACKERS
# ============================================================================
locally_cached_bans = set()
traffic_stats = {"tcp": 0, "udp": 0, "icmp": 0, "bytes": 0}

# ============================================================================
# 5. THE LIVE TRAFFIC HEARTBEAT (Runs in Background)
# ============================================================================
def traffic_heartbeat():
    """Commits traffic stats to the DB every 5 seconds for the Dashboard Matrix."""
    while True:
        time.sleep(5)
        c_tcp = traffic_stats["tcp"]
        c_udp = traffic_stats["udp"]
        c_icmp = traffic_stats["icmp"]
        c_bytes = traffic_stats["bytes"]

        traffic_stats["tcp"] = 0
        traffic_stats["udp"] = 0
        traffic_stats["icmp"] = 0
        traffic_stats["bytes"] = 0

        if c_tcp > 0 or c_udp > 0 or c_icmp > 0:
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO traffic_metrics (tcp_count, udp_count, icmp_count, total_bytes)
                    VALUES (?, ?, ?, ?)
                ''', (c_tcp, c_udp, c_icmp, c_bytes))
                conn.commit()
                conn.close()
            except sqlite3.OperationalError:
                pass 
                
    processed_c2_commands = set()

def c2_polling_heartbeat():
    """Polls the GitHub block_queue.txt every 10 seconds for remote commands."""
    queue_url = "https://raw.githubusercontent.com/vinayak-salian/honeypot-idps/main/logs/block_queue.txt"
    while True:
        time.sleep(10)
        try:
            resp = requests.get(queue_url, timeout=5)
            if resp.status_code == 200:
                lines = resp.text.strip().split('\n')
                for line in lines:
                    if not line.strip(): continue
                    parts = line.split(',')
                    ip_to_ban = parts[0].strip()
                    
                    # If we haven't seen this command yet, execute it!
                    if ip_to_ban and ip_to_ban not in processed_c2_commands and ip_to_ban not in locally_cached_bans:
                        print(f"\n[? C2 COMMAND RECEIVED] Executing remote isolation for {ip_to_ban}")
                        
                        # 1. Execute Kernel Drop
                        os.system(f"sudo iptables -A INPUT -s {ip_to_ban} -j DROP")
                        
                        # 2. Add to RAM cache
                        locally_cached_bans.add(ip_to_ban)
                        processed_c2_commands.add(ip_to_ban)
                        
                        # 3. Save to local Database so it persists across reboots
                        try:
                            conn = sqlite3.connect(DB_PATH)
                            cursor = conn.cursor()
                            reason = parts[1].strip() if len(parts) > 1 else "Remote C2 Intervention"
                            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                            cursor.execute("INSERT OR IGNORE INTO banned_ips (ip, ban_time, reason) VALUES (?, ?, ?)", (ip_to_ban, timestamp, reason))
                            conn.commit()
                            conn.close()
                        except sqlite3.OperationalError:
                            pass # Handle brief DB locks
        except Exception:
            pass # Ignore network blips during polling            

# ============================================================================
# 6. THE DISPATCHER (The Master Sniffer)
# ============================================================================
def master_dispatcher(pkt):
    """Captures traffic ONCE and routes it to the correct ML model."""
    if IP not in pkt:
        return

    src_ip = pkt[IP].src

    # --- A. THE BOUNCER (Eliminate Redundancy) ---
    if src_ip in locally_cached_bans:
        return 

    # --- B. TRAFFIC TALLY (For the Matrix Dashboard) ---
    traffic_stats["bytes"] += len(pkt)
    if TCP in pkt:
        traffic_stats["tcp"] += 1
    elif UDP in pkt:
        traffic_stats["udp"] += 1
    elif ICMP in pkt:
        traffic_stats["icmp"] += 1

    # --- C. ROUTE TO ML BRAINS (The Traffic Cop) ---
    if TCP in pkt:
        portscan_brain(pkt)
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        if dport in [22, 21] or sport in [22, 21]:
            bruteforce_brain(pkt)
    elif UDP in pkt:
        dport = pkt[UDP].dport
        sport = pkt[UDP].sport
        if dport == 53 or sport == 53:
            dns_brain(pkt)

# ============================================================================
# 7. EXECUTION
# ============================================================================
if __name__ == "__main__":
    # Start C2 Polling Thread
    c2_thread = threading.Thread(target=c2_polling_heartbeat, daemon=True)
    c2_thread.start()
    print("[+] Remote C2 Polling Link established.")
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT ip FROM banned_ips")
        for row in cursor.fetchall():
            locally_cached_bans.add(row[0])
        conn.close()
        print(f"[+] The Bouncer loaded {len(locally_cached_bans)} existing bans into RAM cache.")
    except Exception as e:
        print(f"[*] The Bouncer starting with empty cache.")

    heartbeat_thread = threading.Thread(target=traffic_heartbeat, daemon=True)
    heartbeat_thread.start()
    print("[+] Live Traffic Matrix Heartbeat initialized.")

    print("\n[+] Unified Dispatcher activated. Monitoring global network traffic...")

    try:
        # UPDATED: Explicitly set iface to "wlan0"
        sniff(iface="wlan0", prn=master_dispatcher, store=False)
    except KeyboardInterrupt:
        print("\n\n[!] Master shutdown sequence initiated...")
        if malware_process:
            print("[*] Terminating Malware Trap...")
            malware_process.terminate()
        print("[+] System offline. Stay safe.")
        sys.exit(0)
