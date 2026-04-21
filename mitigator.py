#!/usr/bin/env python3
import pandas as pd
import os
import subprocess
import sqlite3
from datetime import datetime

# Path Configuration
QUEUE_PATH = "/home/vinayak/honeypot_project/logs/action_queue.csv"
DB_PATH = "/home/vinayak/honeypot_project/nexus_security.db"

# 1. LOCAL FILTER: Only process these IPs for the local firewall
LOCAL_PREFIX = "10.42.0."
PROTECTED_IPS = ["127.0.0.1", "10.42.0.1"]

def get_mac_for_ip(cursor, ip):
    """Retrieves the MAC address from the census database."""
    try:
        cursor.execute("SELECT mac_address FROM known_devices WHERE ip_address = ?", (ip,))
        result = cursor.fetchone()
        return result[0] if result else None
    except:
        return None

def process_queue():
    if not os.path.exists(QUEUE_PATH): return
    try:
        df = pd.read_csv(QUEUE_PATH)
        if df.empty: return

        conn = sqlite3.connect(DB_PATH, timeout=30)
        cursor = conn.cursor()

        for index, row in df.iterrows():
            ip = row['ip']
            action = row['action']
            
            # --- THE GLOBAL IP FILTER ---
            # Ignores Tailscale/AWS IPs to keep local banned list clean
            if not ip.startswith(LOCAL_PREFIX):
                print(f"[*] IGNORING: {ip} is a Global/Remote IP.")
                continue

            # --- SELF-BLOCK PROTECTION ---
            if ip in PROTECTED_IPS:
                print(f"[!] SECURITY: Block request for protected IP {ip} rejected.")
                continue
            
            mac = get_mac_for_ip(cursor, ip)
            
            if action == "BLOCK":
                print(f"[?? MITIGATOR] ISOLATING ASSET: {ip} " + (f"[{mac}]" if mac else ""))
                
                # Use -I (Insert) to put rules at the TOP of the chain (Priority #1)
                # 1. Block Incoming traffic (INPUT)
                subprocess.run(["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
                # 2. Block Transit traffic (FORWARDing through the Pi)
                subprocess.run(["sudo", "iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"])
                # 3. Block Outgoing traffic (OUTPUT - Pi won't talk back)
                subprocess.run(["sudo", "iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"])
                
                # Layer 2 Block (MAC - prevents IP spoofing bypass)
                if mac:
                    subprocess.run(["sudo", "iptables", "-I", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"])
                
                # Sync with SQLite Table
                cursor.execute("""
                    INSERT OR REPLACE INTO banned_ips (ip, mac, ban_time, reason) 
                    VALUES (?, ?, ?, ?)
                """, (ip, mac, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "C2 Manual Block"))
                
            elif action == "UNBLOCK":
                print(f"[?? MITIGATOR] RELEASING ASSET: {ip}")
                
                # Use -D (Delete) to remove the specific rules
                subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
                subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
                subprocess.run(["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"])
                
                if mac:
                    subprocess.run(["sudo", "iptables", "-D", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"])
                
                # Remove from Database
                cursor.execute("DELETE FROM banned_ips WHERE ip = ?", (ip,))
        
        conn.commit()
        conn.close()

        # Clear the queue file so we don't repeat actions
        with open(QUEUE_PATH, "w") as f:
            f.write("timestamp,ip,action\n")
            
    except Exception as e:
        print(f"Mitigator Error: {e}")

if __name__ == "__main__":
    process_queue()
