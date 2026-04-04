#!/usr/bin/env python3
import sqlite3
import os
import time
import geoip2.database
import geoip2.errors

DB_PATH = '/home/vinayak/honeypot_project/data/honeypot_events.db'
GEO_DB_PATH = '/home/vinayak/honeypot_project/data/GeoLite2-City.mmdb'

def init_db():
    """Initializes the unified honeypot database."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 1. UNIFIED SECURITY EVENTS
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            target_port INTEGER,
            protocol TEXT,
            confidence REAL,
            latitude REAL,
            longitude REAL,
            country TEXT,
            city TEXT,
            action_taken TEXT
        )
    ''')

    # 2. GLOBAL BAN LIST
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS banned_ips (
            ip TEXT PRIMARY KEY,
            ban_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            reason TEXT
        )
    ''')

    # 3. LIVE TRAFFIC TALLY
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

    # 4. NETWORK CENSUS
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS known_devices (
            mac_address TEXT PRIMARY KEY,
            ip_address TEXT,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_trusted INTEGER DEFAULT 0
        )
    ''')

    conn.commit()
    conn.close()
    print(f"[+] Unified Database Initialized at {DB_PATH}")

def is_ip_banned(ip):
    """Checks if an IP is already globally banned."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM banned_ips WHERE ip = ?", (ip,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def log_attack_and_ban(source_ip, attack_type, target_port, protocol, confidence):
    """Logs the attack, records coordinates, and executes global isolation."""
    if is_ip_banned(source_ip):
        return # Skip if already handled

    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    lat, lon, country, city = 0.0, 0.0, "Unknown", "Unknown"

    # ---------------------------------------------------------
    # GEOLOCATION ENGINE (Local Override + Global Lookup)
    # ---------------------------------------------------------
    if source_ip.startswith("192.168.") or source_ip.startswith("10.") or source_ip.startswith("127."):
        # Local Override: Force coordinates to Mumbai for testing
        lat, lon = 19.0760, 72.8777 
        country, city = "India", "Mumbai (Sandbox)"
    else:
        # Global Lookup: Read offline MaxMind Database
        if os.path.exists(GEO_DB_PATH):
            try:
                with geoip2.database.Reader(GEO_DB_PATH) as reader:
                    response = reader.city(source_ip)
                    lat = response.location.latitude if response.location.latitude else 0.0
                    lon = response.location.longitude if response.location.longitude else 0.0
                    country = response.country.name if response.country.name else "Unknown"
                    city = response.city.name if response.city.name else "Unknown"
            except geoip2.errors.AddressNotFoundError:
                print(f"[*] IP {source_ip} not found in Geo database.")
            except Exception as e:
                print(f"[!] GeoIP Error: {e}")
        else:
            print(f"[!] Warning: GeoIP database missing at {GEO_DB_PATH}")

    # ---------------------------------------------------------
    # SYSTEM MODE CHECK (CLOUD vs LOCAL)
    # ---------------------------------------------------------
    mode = os.environ.get("SENTRY_MODE", "LOCAL")
    action_taken = "BLOCKED" if mode == "CLOUD" else "LOGGED (OBSERVER MODE)"

    # ---------------------------------------------------------
    # DATABASE INJECTION & ISOLATION
    # ---------------------------------------------------------
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO security_events 
        (timestamp, source_ip, attack_type, target_port, protocol, confidence, latitude, longitude, country, city, action_taken)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, source_ip, attack_type, target_port, protocol, confidence, lat, lon, country, city, action_taken))

    # Mode Execution
    if mode == "CLOUD":
        cursor.execute('''
            INSERT OR IGNORE INTO banned_ips (ip, reason) VALUES (?, ?)
        ''', (source_ip, attack_type))
        conn.commit()
        conn.close()

        os.system(f"sudo iptables -A INPUT -s {source_ip} -j DROP")
        print(f"\n[🚨 GLOBAL BAN] {source_ip} permanently isolated for: {attack_type} (Conf: {confidence:.2%})")
    else:
        # LOCAL MODE: Just commit the log, skip iptables and banned_ips
        conn.commit()
        conn.close()
        print(f"\n[👀 OBSERVER MODE] Attack logged from {source_ip} ({country}). Auto-ban bypassed to protect VPS tunnel.")

if __name__ == "__main__":
    init_db()
