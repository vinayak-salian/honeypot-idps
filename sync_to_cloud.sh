#!/bin/bash
# Nexus Auto-Sync Engine v2.1
DB_PATH="/home/vinayak/honeypot_project/data/honeypot_events.db"
LOG_DIR="/home/vinayak/honeypot_project/logs"

echo "[*] Synchronizing local Sentry data with Cloud Dashboard..."

# 1. Export Data to CSV
sqlite3 -header -csv $DB_PATH "SELECT * FROM security_events;" > $LOG_DIR/security_events.csv
sqlite3 -header -csv $DB_PATH "SELECT ip as 'Banned IP', ban_time as 'Timestamp', reason as 'Reason' FROM banned_ips;" > $LOG_DIR/banned_ips.csv
sqlite3 -header -csv $DB_PATH "SELECT mac_address, ip_address, last_seen FROM known_devices;" > $LOG_DIR/known_devices.csv
sqlite3 -header -csv $DB_PATH "SELECT * FROM traffic_metrics ORDER BY timestamp DESC LIMIT 60;" > $LOG_DIR/traffic_metrics.csv

# 2. Sync with GitHub
cd /home/vinayak/honeypot_project/
git add .

# Commit only if there are changes
git commit -m "C2-Sync: $(date)" || echo "No local changes to commit."

# THE FIX: Pull remote commands (like block requests) and favor local logs if there is a conflict
git pull origin main -X ours --no-edit

# Final Push
if git push origin main; then
    echo "[?] Sync complete. Dashboard updated."
else
    echo "[!] Sync FAILED. Check your internet or GitHub Token."
    exit 1
fi