#!/usr/bin/env python3
"""
IOT SENTRY | NETWORK CENSUS
Scans the local hotspot and logs connected devices to the database.
"""
import subprocess
import sqlite3
import time
import re

DB_PATH = '/home/vinayak/honeypot_project/data/honeypot_events.db'

def get_connected_devices():
    """Reads the ARP table to find connected devices on the hotspot."""
    devices = []
    try:
        # Run the 'arp -a' command
        result = subprocess.check_output(['arp', '-a']).decode('utf-8')
        # Extract IP and MAC for wlan0 only
        for line in result.split('\n'):
            if 'wlan0' in line: 
                ip_match = re.search(r'\((.*?)\)', line)
                mac_match = re.search(r'at (.*?)\s', line)
                
                if ip_match and mac_match:
                    ip = ip_match.group(1)
                    mac = mac_match.group(1)
                    if mac != "<incomplete>":
                        devices.append((mac, ip))
    except Exception as e:
        print(f"[!] Error scanning network: {e}")
    return devices

def update_database(devices):
    """Updates the known_devices table."""
    if not devices:
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    for mac, ip in devices:
        cursor.execute('''
            INSERT INTO known_devices (mac_address, ip_address, first_seen, last_seen, is_trusted)
            VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 0)
            ON CONFLICT(mac_address) DO UPDATE SET 
            ip_address=excluded.ip_address, 
            last_seen=CURRENT_TIMESTAMP
        ''', (mac, ip))
        print(f"[*] Radar Ping - Device Logged: IP {ip} | MAC {mac}")
        
    conn.commit()
    conn.close()

if __name__ == "__main__":
    print("\n[+] Initializing Sentry Network Census...")
    while True:
        devices = get_connected_devices()
        update_database(devices)
        time.sleep(10) # Scan every 10 seconds