#!/bin/bash
# Nexus Interactive Demo Loop v4.2

DB_PATH="/home/vinayak/honeypot_project/nexus_security.db"
LOG_DIR="/home/vinayak/honeypot_project/logs"
PYTHON_VENV="/home/vinayak/honeypot_project/venv/bin/python"

cd /home/vinayak/honeypot_project/

while true; do
    echo "------------------------------------------------"
    echo "[$(date +%H:%M:%S)] ?? Step 1: Syncing Command Queue..."
    git pull origin main --no-edit > /dev/null 2>&1
    
    if [ -f "mitigator.py" ]; then
        $PYTHON_VENV mitigator.py
    fi

    echo "[$(date +%H:%M:%S)] ?? Step 2: System Metrics..."
    $PYTHON_VENV system_monitor.py

    echo "[$(date +%H:%M:%S)] ??? Step 3: Exporting Logs..."
    # Add this to Step 3 in sync_to_cloud.sh
    sqlite3 -header -csv $DB_PATH "SELECT timestamp, source_ip, domain FROM web_history ORDER BY timestamp DESC LIMIT 100;" > $LOG_DIR/web_history.csv    
    # 1. Export ATTACKS (Matches dashboard expectations)
    sqlite3 -header -csv $DB_PATH "SELECT timestamp, source_ip, attack_type, target_port, protocol, confidence, evidence, latitude, longitude, country, city FROM attack_logs;" > $LOG_DIR/security_events.csv

    # 2. Export DEVICES (Matches the 'ip_address' requirement for Pandas)
    sqlite3 -header -csv $DB_PATH "SELECT mac_address, ip_address, last_seen FROM known_devices;" > $LOG_DIR/known_devices.csv

    # 3. Export BANNED IPs (REQUIRED for the Smart Toggle Button to work)
    sqlite3 -header -csv $DB_PATH "SELECT ip as 'Banned IP', ban_time as 'Timestamp', reason as 'Reason' FROM banned_ips;" > $LOG_DIR/banned_ips.csv

    # 4. Export TRAFFIC
    sqlite3 -header -csv $DB_PATH "SELECT timestamp, tcp_count, udp_count, icmp_count, total_bytes FROM traffic_metrics ORDER BY timestamp DESC LIMIT 60;" > $LOG_DIR/traffic_metrics.csv
    
    chmod 666 $LOG_DIR/*.
    

    echo "[$(date +%H:%M:%S)] ?? Step 4: Pushing to Dashboard..."
    git add $LOG_DIR/*.csv
    sleep 1 
    git commit -m "Nexus-Pulse: $(date +%H:%M:%S)" > /dev/null 2>&1
    
    if git push origin main; then
        echo "[$(date +%H:%M:%S)] ? Cycle Complete."
    else
        echo "[!] WARNING: Push failed."
    fi

    echo "[*] Sleeping for 20 seconds..."
    sleep 20
done
