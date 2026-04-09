import os
import sqlite3
import time
from collections import defaultdict
from scapy.all import IP, TCP

# CONFIG
DB_PATH = '/home/vinayak/honeypot_project/nexus_security.db'
flows = defaultdict(lambda: {'ports': set(), 'start_time': None, 'blocked': False})

# SET TO 2 FOR DEMO SENSITIVITY
PORT_THRESHOLD = 2 

def analyze_and_block(src_ip):
    if flows[src_ip]['blocked']: return
    
    num_ports = len(flows[src_ip]['ports'])
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    
    print(f"[??] TRIGGERING DB WRITE FOR {src_ip} | Ports: {num_ports}")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        # Direct insert - skipping ML for this diagnostic check
        cursor.execute('''
            INSERT INTO attack_logs (timestamp, source_ip, attack_type, confidence, evidence, latitude, longitude, country, city)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, src_ip, "PortScan", 0.99, f"Probed Ports: {list(flows[src_ip]['ports'])}", 19.076, 72.877, "India", "Mumbai"))
        conn.commit()
        conn.close()
        flows[src_ip]['blocked'] = True
        print(f"[?] Successfully wrote PortScan to Database.")
    except Exception as e:
        print(f"[!] DB Error: {e}")

def packet_callback(pkt):
    if IP not in pkt or TCP not in pkt: return
    
    src_ip = pkt[IP].src
    dst_port = pkt[TCP].dport

    # Ignore traffic coming FROM the Pi
    if src_ip == "10.42.0.1" or src_ip == "127.0.0.1": return

    # LOG EVERY PORT SEEN
    if flows[src_ip]['start_time'] is None:
        flows[src_ip]['start_time'] = time.time()
    
    if dst_port not in flows[src_ip]['ports']:
        flows[src_ip]['ports'].add(dst_port)
        print(f"[DEBUG] {src_ip} scanned new port: {dst_port} (Total: {len(flows[src_ip]['ports'])})")

    # Trigger immediately if we see enough variety
    if len(flows[src_ip]['ports']) >= PORT_THRESHOLD:
        analyze_and_block(src_ip)
