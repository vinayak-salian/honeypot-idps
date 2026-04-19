#!/bin/bash
# Nexus Sentry: Selective Demo Reset v5.2
# Upgrade: Clears Port 5228 "Ghost Logs" and Prepares Clean Mode B Session

LOG_DIR="/home/vinayak/honeypot_project/logs"
DB_PATH="/home/vinayak/honeypot_project/nexus_security.db"

echo "[*] NEXUS SENTRY: INITIATING SELECTIVE RESET..."

# 1. SURGICAL DATABASE PURGE
# We remove all local traffic logs (10.42.0.x) including the 5228 "ghost scans"
sqlite3 $DB_PATH "DELETE FROM attack_logs WHERE source_ip LIKE '10.42.0.%';"

# Clear other local-only tracking tables for a fresh start
sqlite3 $DB_PATH "DELETE FROM known_devices;"
sqlite3 $DB_PATH "DELETE FROM web_history;"
sqlite3 $DB_PATH "DELETE FROM banned_ips;"
sqlite3 $DB_PATH "DELETE FROM traffic_metrics;"

echo "[+] SQLite Database: Local Subnet Purged | Global Archive Preserved"

# 2. FLUSH FIREWALL
# Removes any previous demo blocks to ensure your laptop (.48) can communicate
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
# Re-enable routing/forwarding for the Infection Zone
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
echo "[+] IPTables: FLUSHED (All network blocks lifted)"

# 3. RESET CSV LOGS WITH HEADERS
# We re-initialize the local-only CSVs to wipe them from the Cloud Dashboard.
# NEW: We specifically reset local_events.csv to clear the Port 5228 flooding.
HEADER="timestamp,source_ip,attack_type,confidence,evidence,latitude,longitude,country,city"
echo "$HEADER" > $LOG_DIR/local_events.csv
echo "mac_address,ip_address,last_seen" > $LOG_DIR/known_devices.csv
echo "timestamp,source_ip,domain" > $LOG_DIR/web_history.csv
echo "Banned IP,Timestamp,Reason" > $LOG_DIR/banned_ips.csv
echo "timestamp,tcp_count,udp_count,icmp_count,total_bytes" > $LOG_DIR/traffic_metrics.csv
echo "timestamp,ip,action" > $LOG_DIR/action_queue.csv

# Note: security_events.csv is NOT wiped to preserve the Mode A Global Botnet archive.

# Ensure permissions
chmod 666 $LOG_DIR/*.csv
echo "[+] CSV Logs: REINITIALIZED"

# 4. PUSH STATE TO GITHUB
# This clears the dashboard for the judges IMMEDIATELY.
cd /home/vinayak/honeypot_project/
git add logs/*.csv
git commit -m "Demo-Reset: Purging Local Noise and 5228 Ghost Logs" > /dev/null 2>&1
git push origin main > /dev/null 2>&1
echo "[+] Cloud Dashboard: SYNCED & CLEARED"
