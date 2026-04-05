#!/bin/bash
# Nexus Auto-Sync Engine v2.2 (SIES GST SOC Edition)
DB_PATH="/home/vinayak/honeypot_project/data/honeypot_events.db"
LOG_DIR="/home/vinayak/honeypot_project/logs"

# Move to the project root
cd /home/vinayak/honeypot_project/

echo "[*] Step 1: Generating Fresh System Health Data..."
python3 system_monitor.py

echo "[*] Step 2: Exporting Security Events from SQLite..."
sqlite3 -header -csv $DB_PATH "SELECT * FROM security_events;" > $LOG_DIR/security_events.csv
sqlite3 -header -csv $DB_PATH "SELECT ip as 'Banned IP', ban_time as 'Timestamp', reason as 'Reason' FROM banned_ips;" > $LOG_DIR/banned_ips.csv
sqlite3 -header -csv $DB_PATH "SELECT mac_address, ip_address, last_seen FROM known_devices;" > $LOG_DIR/known_devices.csv
sqlite3 -header -csv $DB_PATH "SELECT * FROM traffic_metrics ORDER BY timestamp DESC LIMIT 60;" > $LOG_DIR/traffic_metrics.csv

echo "[*] Step 3: Synchronizing with Cloud Dashboard..."

# FORCE Git to see the health file (incase .gitignore is blocking it)
git add -f $LOG_DIR/system_status.csv
git add .

# Commit changes (don't exit if there's nothing new)
git commit -m "C2-Sync: $(date)" || echo "No changes detected since last sync."

# Pull remote changes (favor local logs in case of conflict)
git pull origin main -X ours --no-edit

# FINAL PUSH
if git push origin main; then
    echo "[!] SUCCESS: Pi Heartbeat & Logs pushed to Cloud."
else
    echo "[!] ERROR: Sync failed. Check internet or GitHub credentials."
    exit 1
fi
