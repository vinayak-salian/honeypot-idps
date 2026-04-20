#!/usr/bin/env python3
import subprocess
import sqlite3
import time
import re
import os
import sys

DB_PATH = '/home/vinayak/honeypot_project/nexus_security.db'

def get_connected_devices():
    devices = []
    try:
        # Added --retry and --timeout to handle mobile hotspot instability
        print("[*] Sending ARP probes on wlan0...")
        result = subprocess.check_output(
            ['sudo', 'arp-scan', '--interface=wlan0', '--localnet', '--retry=2', '--timeout=200'],
            stderr=subprocess.STDOUT
        ).decode('utf-8')
        
        pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})')
        for line in result.split('\n'):
            match = pattern.search(line)
            if match:
                ip, mac = match.groups()
                if not ip.endswith('.1'): 
                    devices.append((mac, ip))
        print(f"[?] Scan complete. Found {len(devices)} devices.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Arp-scan failed: {e.output.decode()}")
    except Exception as e:
        print(f"[!] Unexpected Error: {e}")
    return devices

def update_database(devices):
    if not devices: 
        print("[*] Radar Ping - No active devices detected.")
        return
    
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30)
        cursor = conn.cursor()
        for mac, ip in devices:
            cursor.execute('''
                INSERT INTO known_devices (mac_address, ip_address, last_seen)
                VALUES (?, ?, datetime('now', 'localtime'))
                ON CONFLICT(mac_address) DO UPDATE SET 
                ip_address=excluded.ip_address, 
                last_seen=datetime('now', 'localtime')
            ''', (mac, ip))
            print(f"[*] Radar Ping - Device Logged: {ip} [{mac}]")
        conn.commit()
    except sqlite3.OperationalError as e:
        print(f"[!] Database Locked: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    # Ensure DB file is accessible
    if not os.path.exists(os.path.dirname(DB_PATH)):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    print("[+] Sentry Radar ACTIVE (Active ARP Mode)...")
    while True:
        found = get_connected_devices()
        update_database(found)
        print(f"[*] Sleeping for 15s... (Time: {time.strftime('%H:%M:%S')})")
        time.sleep(15)
