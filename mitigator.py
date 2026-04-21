#!/usr/bin/env python3
import pandas as pd
import os
import subprocess
import sqlite3
import time
from datetime import datetime

# Path Configuration
BASE_DIR = "/home/vinayak/honeypot_project"
QUEUE_PATH = os.path.join(BASE_DIR, "logs/action_queue.csv")
DB_PATH = os.path.join(BASE_DIR, "nexus_security.db")

# 1. LOCAL FILTER: Only process these IPs for the local firewall
LOCAL_PREFIX = "10.42.0."
PROTECTED_IPS = ["127.0.0.1", "10.42.0.1"]

def sync_from_cloud():
    """Forces the Pi to pull the latest commands from GitHub."""
    try:
        # Reset local changes to the queue file to avoid merge conflicts
        subprocess.run(["git", "checkout", QUEUE_PATH], cwd=BASE_DIR, capture_output=True)
        # Pull latest data from main
        subprocess.run(["git", "pull", "origin", "main", "--quiet"], cwd=BASE_DIR, capture_output=True)
    except Exception as e:
        print(f"[!] Sync Error: {e}")

def get_mac_for_ip(cursor, ip):
    """Retrieves the MAC address from the census database."""
    try:
        cursor.execute("SELECT mac_address FROM known_devices WHERE ip_address = ?", (ip,))
        result = cursor.fetchone()
        return result[0] if result else None
    except:
        return None

def process_queue():
    if not os.path.exists(QUEUE_PATH): 
        return

    try:
        # Read the queue; error handling for malformed CSVs
        df = pd.read_csv(QUEUE_PATH)
        if df.empty or len(df.columns) < 3: 
            return

        conn = sqlite3.connect(DB_PATH, timeout=30)
        cursor = conn.cursor()
        actions_taken = False

        for index, row in df.iterrows():
            if 'ip' not in row or 'action' not in row: continue
            ip = str(row['ip'])
            action = str(row['action'])
            
            # --- THE GLOBAL IP FILTER ---
            if not ip.startswith(LOCAL_PREFIX):
                continue

            # --- SELF-BLOCK PROTECTION ---
            if ip in PROTECTED_IPS:
                print(f"[!] SECURITY: Block for {ip} rejected (Protected).")
                continue
            
            mac = get_mac_for_ip(cursor, ip)
            
            if action == "BLOCK":
                print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚨 ISOLATING: {ip} " + (f"[{mac}]" if mac else ""))
                subprocess.run(["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
                subprocess.run(["sudo", "iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"])
                subprocess.run(["sudo", "iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"])
                if mac:
                    subprocess.run(["sudo", "iptables", "-I", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"])
                
                cursor.execute("""
                    INSERT OR REPLACE INTO banned_ips (ip, mac, ban_time, reason) 
                    VALUES (?, ?, ?, ?)
                """, (ip, mac, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "C2 Manual Block"))
                actions_taken = True
                
            elif action == "UNBLOCK":
                print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔓 RELEASING: {ip}")
                subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], stderr=subprocess.DEVNULL)
                subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], stderr=subprocess.DEVNULL)
                subprocess.run(["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"], stderr=subprocess.DEVNULL)
                if mac:
                    subprocess.run(["sudo", "iptables", "-D", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"], stderr=subprocess.DEVNULL)
                
                cursor.execute("DELETE FROM banned_ips WHERE ip = ?", (ip,))
                actions_taken = True
        
        conn.commit()
        conn.close()

        # If we processed rules, clear the file and push the "Clear" back to GitHub
        if actions_taken:
            with open(QUEUE_PATH, "w") as f:
                f.write("timestamp,ip,action\n")
            subprocess.run(["git", "add", QUEUE_PATH], cwd=BASE_DIR)
            subprocess.run(["git", "commit", "-m", "Nexus-Pulse: Queue Processed"], cwd=BASE_DIR)
            subprocess.run(["git", "push", "origin", "main", "--quiet"], cwd=BASE_DIR)
            
    except Exception as e:
        print(f"Mitigator Runtime Error: {e}")

if __name__ == "__main__":
    print(f"[*] Nexus Mitigator Service Started [Interval: 7s]")
    print(f"[*] Monitoring: {QUEUE_PATH}")
    
    while True:
        # 1. Pull from Cloud
        sync_from_cloud()
        # 2. Process Commands
        process_queue()
        # 3. Wait before next check
        time.sleep(7)
