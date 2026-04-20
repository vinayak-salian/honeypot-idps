#!/bin/bash
# Nexus Interactive Demo Loop v4.7
# Upgrade: Added .timeout 5000 for concurrent DB access

DB_PATH="/home/vinayak/honeypot_project/nexus_security.db"
LOG_DIR="/home/vinayak/honeypot_project/logs"
PYTHON_VENV="/home/vinayak/honeypot_project/venv/bin/python"

# Capture Today's date for Mode B filtering
TODAY=$(date "+%Y-%m-%d")
echo "[*] Demo Day Mode: Filtering Local Sentinel for $TODAY"

cd /home/vinayak/honeypot_project/

while true; do
    echo "------------------------------------------------"
    echo "[$(date +%H:%M:%S)] ?? Step 1: Force Syncing with GitHub..."
    git pull origin main --rebase > /dev/null 2>&1
    
    if [ -f "mitigator.py" ]; then
        $PYTHON_VENV mitigator.py
    fi

    echo "[$(date +%H:%M:%S)] ?? Step 2: System Metrics..."
    $PYTHON_VENV system_monitor.py

    echo "[$(date +%H:%M:%S)] ?? Step 3: Exporting Logs (Dual-Stream)..."
    
    COLS="timestamp,source_ip,attack_type,confidence,evidence,latitude,longitude,country,city"

    # --- MODE A: GLOBAL WATCHTOWER (Historical/Forever) ---
    sqlite3 -header -csv -cmd ".timeout 5000" $DB_PATH "SELECT $COLS FROM attack_logs WHERE TRIM(source_ip) NOT LIKE '10.42.0.%' ORDER BY timestamp DESC;" > $LOG_DIR/security_events.csv

    # --- MODE B: LOCAL SENTINEL (Today Only) ---
    sqlite3 -header -csv -cmd ".timeout 5000" $DB_PATH "SELECT $COLS FROM attack_logs WHERE TRIM(source_ip) LIKE '10.42.0.%' AND timestamp LIKE '$TODAY%' ORDER BY timestamp DESC;" > $LOG_DIR/local_events.csv

    # --- PRESERVED FEATURES (Local context also set to Today) ---
    sqlite3 -header -csv -cmd ".timeout 5000" $DB_PATH "SELECT timestamp,source_ip,domain FROM web_history WHERE timestamp LIKE '$TODAY%' ORDER BY timestamp DESC LIMIT 100;" > $LOG_DIR/web_history.csv    
    
    sqlite3 -header -csv -cmd ".timeout 5000" $DB_PATH "SELECT mac_address,ip_address,last_seen FROM known_devices;" > $LOG_DIR/known_devices.csv
    
    sqlite3 -header -csv -cmd ".timeout 5000" $DB_PATH "SELECT ip as 'Banned IP',ban_time as 'Timestamp',reason as 'Reason' FROM banned_ips;" > $LOG_DIR/banned_ips.csv
    
    sqlite3 -header -csv -cmd ".timeout 5000" $DB_PATH "SELECT timestamp,tcp_count,udp_count,icmp_count,total_bytes FROM traffic_metrics ORDER BY timestamp DESC LIMIT 60;" > $LOG_DIR/traffic_metrics.csv
    
    chmod 666 $LOG_DIR/*.csv

    echo "[$(date +%H:%M:%S)] ?? Step 4: Pushing to Dashboard..."
    git add $LOG_DIR/*.csv
    git commit -m "Nexus-Pulse: Demo Update $(date +%H:%M:%S)" > /dev/null 2>&1
    
    if git push origin main; then
        echo "[$(date +%H:%M:%S)] ? Cycle Complete."
    else
        echo "[!] Push failed. Running Emergency Git Reset..."
        git fetch origin
        git reset --soft origin/main
    fi

    echo "[*] Sleeping for 20 seconds..."
    sleep 60
done
