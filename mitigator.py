#!/usr/bin/env python3
import pandas as pd
import os
import subprocess
import sqlite3
from datetime import datetime

# Path Configuration
QUEUE_PATH = "/home/vinayak/honeypot_project/logs/action_queue.csv"
DB_PATH = "/home/vinayak/honeypot_project/nexus_security.db"

# 1. LOCAL FILTER: Only process these IPs for the banned list/firewall
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
            if not ip.startswith(LOCAL_PREFIX):
                print(f"[*] IGNORING: {ip} is a Global/Remote IP (Not in Local Mode scope).")
                continue

            # --- SELF-BLOCK PROTECTION ---
            if ip in PROTECTED_IPS:
                print(f"[!] SECURITY: Block request for protected IP {ip} rejected.")
                continue
            
            mac = get_mac_for_ip(cursor, ip)
            
            if action == "BLOCK":
                print(f"[?? MITIGATOR] LOCAL ISOLATION: {ip} " + (f"[{mac}]" if mac else ""))
                
                # Layer 3 Block (IP)
                subprocess.run(["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
                subprocess.run(["sudo", "iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"])
                
                # Layer 2 Block (MAC - The 100% Fix)
                if mac:
                    subprocess.run(["sudo", "iptables", "-I", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"])
                
                # Update Local Banned List
                cursor.execute("""
                    INSERT OR REPLACE INTO banned_ips (ip, mac, ban_time, reason) 
                    VALUES (?, ?, ?, ?)
                """, (ip, mac, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "Manual Local Block"))
                
            elif action == "UNBLOCK":
                print(f"[?? MITIGATOR] RELEASING ASSET: {ip}")
                subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
                subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
                if mac:
                    subprocess.run(["sudo", "iptables", "-D", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"])
                
                cursor.execute("DELETE FROM banned_ips WHERE ip = ?", (ip,))
        
        conn.commit()
        conn.close()

        # Reset the queue file headers
        with open(QUEUE_PATH, "w") as f:
            f.write("timestamp,ip,action\n")
            
    except Exception as e:
        print(f"Mitigator Error: {e}")

if __name__ == "__main__":
    process_queue()
