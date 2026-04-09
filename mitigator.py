#!/usr/bin/env python3
import pandas as pd
import os
import subprocess
import sqlite3
from datetime import datetime

# Path Configuration
QUEUE_PATH = "/home/vinayak/honeypot_project/logs/action_queue.csv"
DB_PATH = "/home/vinayak/honeypot_project/nexus_security.db"

def process_queue():
    if not os.path.exists(QUEUE_PATH): return
    try:
        df = pd.read_csv(QUEUE_PATH)
        if df.empty: return

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        for index, row in df.iterrows():
            ip = row['ip']
            action = row['action']
            
            if action == "BLOCK":
                print(f"[??? MITIGATOR] TOTAL ISOLATION: {ip}")
                # 1. Firewall Action (Block both Local Access and Internet Forwarding)
                subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
                subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"])
                
                # 2. Update Database so Dashboard knows it's official
                cursor.execute("INSERT OR IGNORE INTO banned_ips (ip, ban_time, reason) VALUES (?, ?, ?)", 
                               (ip, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "C2 Manual Block"))
                
            elif action == "UNBLOCK":
                print(f"[?? MITIGATOR] RELEASING ASSET: {ip}")
                # 1. Remove Firewall Rules
                subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
                subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
                
                # 2. Remove from Database
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
