#!/usr/bin/env python3
"""
IOT SENTRY | NETWORK CENSUS v2.0
Active ARP scanning for 99% Local Asset Accuracy.
"""
import subprocess
import sqlite3
import time
import re
import os

# FIXED: Pointing to your main DB so it shows on the dashboard
DB_PATH = '/home/vinayak/honeypot_project/nexus_security.db'

def get_connected_devices():
    devices = []
    try:
        # ACTIVE SCAN: Forces devices like your laptop to respond
        result = subprocess.check_output(['sudo', 'arp-scan', '--interface=wlan0', '--localnet']).decode('utf-8')
        pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})')
        for line in result.split('\n'):
            match = pattern.search(line)
            if match:
                ip, mac = match.groups()
                if not ip.endswith('.1'): # Ignore the Pi itself
                    devices.append((mac, ip))
    except Exception as e:
        print(f"[!] Scan Error: {e}")
    return devices

def update_database(devices):
    if not devices: return
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    for mac, ip in devices:
        cursor.execute('''
            INSERT INTO known_devices (mac_address, ip_address, last_seen)
            VALUES (?, ?, datetime('now', 'localtime'))
            ON CONFLICT(mac_address) DO UPDATE SET 
            ip_address=excluded.ip_address, 
            last_seen=datetime('now', 'localtime')
        ''', (mac, ip))
        print(f"[*] Radar Ping - Device Logged: {ip}")
    conn.commit()
    conn.close()

if __name__ == "__main__":
    print("[+] Sentry Radar ACTIVE (Every 15s)...")
    while True:
        update_database(get_connected_devices())
        time.sleep(15)
