#!/bin/bash
# /home/vinayak/honeypot_project/sync_to_cloud.sh

DB_PATH="/home/vinayak/honeypot_project/data/honeypot_events.db"
LOG_DIR="/home/vinayak/honeypot_project/logs"

echo "[*] Synchronizing local Sentry data with Cloud Dashboard..."

# Export all relevant tables to CSV
sqlite3 -header -csv $DB_PATH "SELECT * FROM security_events;" > $LOG_DIR/security_events.csv
sqlite3 -header -csv $DB_PATH "SELECT ip as 'Banned IP', ban_time as 'Timestamp', reason as 'Reason' FROM banned_ips;" > $LOG_DIR/banned_ips.csv
sqlite3 -header -csv $DB_PATH "SELECT * FROM traffic_metrics ORDER BY timestamp DESC LIMIT 60;" > $LOG_DIR/traffic_metrics.csv
sqlite3 -header -csv $DB_PATH "SELECT * FROM known_devices;" > $LOG_DIR/known_devices.csv

# Push to GitHub
cd /home/vinayak/honeypot_project/
git add logs/*.csv
git commit -m "C2-Sync: $(date)"
git push origin main

echo "[?] Sync complete. Dashboard updated."