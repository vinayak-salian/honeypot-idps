#!/usr/bin/env python3
"""
IOT SENTRY | UNIFIED DATABASE HANDLER
Manages SQLite storage for banned IPs, attack logs, and traffic metrics.
"""

import sqlite3
import os
import time

# 1. DATABASE CONFIGURATION
DB_PATH = '/home/vinayak/honeypot_project/nexus_security.db'

def init_db():
    """Initializes the database and creates required tables if they don't exist."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Table for active IP bans
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS banned_ips (
            ip TEXT PRIMARY KEY,
            ban_time TEXT,
            reason TEXT
        )
    ''')

    # Table for detailed attack logs (for historical analysis)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            attack_type TEXT,
            target_port INTEGER,
            protocol TEXT,
            confidence REAL
        )
    ''')

    # Table for real-time traffic metrics
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            tcp_count INTEGER,
            udp_count INTEGER,
            icmp_count INTEGER,
            total_bytes INTEGER
        )
    ''')

    conn.commit()
    conn.close()
    # print(f"[?] Database initialized at {DB_PATH}")

def log_attack_and_ban(source_ip, attack_type, target_port, protocol, confidence):
    """
    Logs an attack to the DB and adds the IP to the banned list.
    Used by all ML detectors (DNS, BruteForce, PortScan, Malware).
    """
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # 1. Log the individual attack event
        cursor.execute('''
            INSERT INTO attack_logs (timestamp, source_ip, attack_type, target_port, protocol, confidence)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (timestamp, source_ip, attack_type, target_port, protocol, confidence))

        # 2. Add to banned_ips table (Persistence)
        cursor.execute('''
            INSERT OR IGNORE INTO banned_ips (ip, ban_time, reason)
            VALUES (?, ?, ?)
        ''', (source_ip, timestamp, attack_type))

        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[!] Database Logging Error: {e}")
        return False

# Automatically initialize on import
if not os.path.exists(DB_PATH):
    init_db()
else:
    # Ensure tables exist even if file exists
    init_db()
