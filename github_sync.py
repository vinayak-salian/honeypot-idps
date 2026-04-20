#!/usr/bin/env python3
"""
IOT SENTRY | CLOUD SYNC ENGINE
Extracts local SQLite data, formats to CSV, and pushes to GitHub.
"""
import sqlite3
import pandas as pd
import os
import time
import subprocess

DB_PATH = '/home/vinayak/honeypot_project/data/honeypot_events.db'
REPO_DIR = '/home/vinayak/honeypot-idps' 
LOGS_DIR = os.path.join(REPO_DIR, 'logs')

# Ensure the logs directory exists inside the git repo
os.makedirs(LOGS_DIR, exist_ok=True)

def export_data():
    """Extracts data from SQLite and overwrites the CSV files."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30)
        
        # SQL Queries mapped exactly to your Cloud Dashboard's expected filenames
        exports = {
            "portscan_log.csv": "SELECT timestamp, source_ip, attack_type, target_port, confidence, country, city FROM security_events WHERE attack_type LIKE '%Scan%' ORDER BY timestamp DESC",
            "malware_delivery_log.csv": "SELECT timestamp, source_ip, attack_type, target_port, confidence, country, city FROM security_events WHERE attack_type LIKE '%Malware%' ORDER BY timestamp DESC",
            "bruteforce_log.csv": "SELECT timestamp, source_ip, attack_type, target_port, confidence, country, city FROM security_events WHERE attack_type LIKE '%Brute%' ORDER BY timestamp DESC",
            "dns_spoof_log.csv": "SELECT timestamp, source_ip, attack_type, target_port, confidence, country, city FROM security_events WHERE attack_type LIKE '%DNS%' ORDER BY timestamp DESC"
        }
        
        for filename, query in exports.items():
            df = pd.read_sql_query(query, conn)
            df.to_csv(os.path.join(LOGS_DIR, filename), index=False)
            
        # The Banned IPs text file
        banned_df = pd.read_sql_query("SELECT ip FROM banned_ips ORDER BY ban_time DESC", conn)
        banned_df.to_csv(os.path.join(LOGS_DIR, "blocked_ips.txt"), index=False, header=False)
        
        conn.close()
        return True
    except Exception as e:
        print(f"[!] Database export error: {e}")
        return False

def push_to_github():
    """Commits and pushes changes if new attacks were logged."""
    try:
        os.chdir(REPO_DIR)
        
        # Check if the CSVs actually changed before pushing
        status = subprocess.check_output(['git', 'status', '--porcelain']).decode('utf-8')
        if not status:
            print(f"[{time.strftime('%H:%M:%S')}] No new attacks detected. Skipping sync.")
            return

        # Add, Commit, and Push via the existing PAT configuration
        subprocess.run(['git', 'add', 'logs/*'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['git', 'commit', '-m', 'Automated Sentry Log Sync'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['git', 'push'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        print(f"[{time.strftime('%H:%M:%S')}] ?? Threat Intelligence successfully synced to GitHub Cloud!")
    except subprocess.CalledProcessError as e:
        print(f"[!] Git Sync Failed. Verify your PAT and remote branch. Error: {e}")

if __name__ == "__main__":
    print("[+] Initializing Nexus Cloud Sync Engine...")
    while True:
        if export_data():
            push_to_github()
        # Wait 60 seconds before the next sync
        time.sleep(60)
