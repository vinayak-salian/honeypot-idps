#!/bin/bash
# Nexus Interactive Demo Loop v3.0
# Optimized for SIES GST Live Demo (USB Tethering Mode)

DB_PATH="/home/vinayak/honeypot_project/data/honeypot_events.db"
LOG_DIR="/home/vinayak/honeypot_project/logs"

# Move to the project root
cd /home/vinayak/honeypot_project/

echo "?? Nexus Sentry: Starting Live Interactive Loop..."
echo "Press [CTRL+C] to stand down the system."

while true; do
    echo "------------------------------------------------"
    echo "[$(date +%H:%M:%S)] ?? Step 1: Checking for Cloud Commands..."
    
    # 1. PULL: Fetch any 'BLOCK' or 'UNBLOCK' commands from the Dashboard
    # We pull first so we can act on commands before we report new data
    git pull origin main --no-edit > /dev/null 2>&1
    
    # 2. ACT: Run the mitigator to process the action_queue.csv
    if [ -f "mitigator.py" ]; then
        python3 mitigator.py
    fi

    echo "[$(date +%H:%M:%S)] ?? Step 2: Generating Fresh Metrics..."
    python3 system_monitor.py

    echo "[$(date +%H:%M:%S)] ?? Step 3: Exporting SQLite Logs..."
    sqlite3 -header -csv $DB_PATH "SELECT * FROM security_events;" > $LOG_DIR/security_events.csv
    sqlite3 -header -csv $DB_PATH "SELECT ip as 'Banned IP', ban_time as 'Timestamp', reason as 'Reason' FROM banned_ips;" > $LOG_DIR/banned_ips.csv
    sqlite3 -header -csv $DB_PATH "SELECT mac_address, ip_address, last_seen FROM known_devices;" > $LOG_DIR/known_devices.csv
    sqlite3 -header -csv $DB_PATH "SELECT * FROM traffic_metrics ORDER BY timestamp DESC LIMIT 60;" > $LOG_DIR/traffic_metrics.csv

    echo "[$(date +%H:%M:%S)] ?? Step 4: Pushing to Dashboard..."
    
    # Force add the system status and add everything else
    git add -f $LOG_DIR/system_status.csv
    git add .
    
    # Commit with a timestamped message
    git commit -m "C2-Pulse: $(date +%H:%M:%S)" > /dev/null 2>&1
    
    # Final Push to update the Cloud UI
    if git push origin main > /dev/null 2>&1; then
        echo "[$(date +%H:%M:%S)] ? Cycle Complete. Dashboard Updated."
    else
        echo "[!] WARNING: Push failed. Check internet connection."
    fi

    echo "[*] Sleeping for 20 seconds..."
    sleep 20
done