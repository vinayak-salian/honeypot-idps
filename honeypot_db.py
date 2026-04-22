#!/usr/bin/env python3
"""
IOT SENTRY | UNIFIED DATABASE HANDLER v4.2
Manages SQLite storage for banned IPs, attack logs, known devices, and traffic metrics.
"""
 
import sqlite3
import os
import time
 
# 1. DATABASE CONFIGURATION
DB_PATH = '/home/vinayak/honeypot_project/nexus_security.db'
 
def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    cursor = conn.cursor()
    # ... (other tables: banned_ips, attack_logs, traffic_metrics, known_devices) ...
    
    # ADD THIS TABLE:
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS web_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            domain TEXT
        )
    ''')
    conn.commit()
    conn.close()
    """Initializes the database and creates required tables if they don't exist."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
 
    # Table for active IP bans
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS banned_ips (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            ban_time TEXT,
            reason TEXT
        )
    ''')
    # Migration: add mac column to existing DBs created without it
    try:
        cursor.execute("ALTER TABLE banned_ips ADD COLUMN mac TEXT")
    except Exception:
        pass  # Column already exists — safe to ignore
 
    # UPDATED: Added 'evidence' and 'geolocation' columns for the Dashboard
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            attack_type TEXT,
            target_port INTEGER,
            protocol TEXT,
            confidence REAL,
            evidence TEXT,
            latitude REAL,
            longitude REAL,
            country TEXT,
            city TEXT
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
 
    # ADDED: Table for known devices (Fixes the "missing devices" dashboard issue)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS known_devices (
            mac_address TEXT PRIMARY KEY,
            ip_address TEXT,
            last_seen TEXT
        )
    ''')
 
    conn.commit()
    conn.close()
 
def log_attack_and_ban(source_ip, attack_type, target_port, protocol, confidence, evidence="ML Analysis"):
    """
    Logs an attack to the DB. 
    Includes 'evidence' to show the 'Why' on the dashboard.
    """
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    
    # Geolocation for SIES GST (Mumbai)
    LAT, LONG = 19.076, 72.877
    COUNTRY, CITY = "India", "Mumbai"
 
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
 
        # 1. Log with full columns for Dashboard
        cursor.execute('''
            INSERT INTO attack_logs 
            (timestamp, source_ip, attack_type, target_port, protocol, confidence, evidence, latitude, longitude, country, city)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, source_ip, attack_type, target_port, protocol, confidence, evidence, LAT, LONG, COUNTRY, CITY))
 
        # 2. Add to banned_ips table (Optional: You can comment this if you want strictly manual bans)
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
init_db()
