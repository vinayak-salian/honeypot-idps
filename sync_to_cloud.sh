#!/bin/bash
# Nexus Interactive Demo Loop v3.1
# Optimized for SIES GST Live Demo (USB Tethering Mode)

# FIX 1: Point to the actual DB we just created
DB_PATH="/home/vinayak/honeypot_project/nexus_security.db"
LOG_DIR="/home/vinayak/honeypot_project/logs"
PYTHON_VENV="/home/vinayak/honeypot_project/venv/bin/python"

# Move to the project root
cd /home/vinayak/honeypot_project/

echo "??? Nexus Sentry: Starting Live Interactive Loop..."
echo "Press [CTRL+C] to stand down the system."

while true; do
    echo "------------------------------------------------"
    echo "[$(date +%H:%M:%S)] ?? Step 1: Checking for Cloud Commands..."
    
    # Pull first to act on remote blocks/unblocks
    git pull origin main --no-edit > /dev/null 2>&1
    
    # 2. ACT: Use venv python to run the mitigator
    if [ -f "mitigator.py" ]; then
        $PYTHON_VENV mitigator.py
    fi

    echo "[$(date +%H:%M:%S)] ?? Step 2: Generating Fresh Metrics..."
    # FIX 2: Using VENV python fixes the 'psutil' ModuleNotFoundError
    $PYTHON_VENV system_monitor.py

    echo "[$(date +%H:%M:%S)] ??? Step 3: Exporting SQLite Logs..."
    # FIX 3: Updated table names to match our honeypot_db.py schema
    sqlite3 -header -csv $DB_PATH "SELECT * FROM attack_logs;" > $LOG_DIR/security_events.csv
    sqlite3 -header -csv $DB_PATH "SELECT ip as 'Banned IP', ban_time as 'Timestamp', reason as 'Reason' FROM banned_ips;" > $LOG_DIR/banned_ips.csv
    sqlite3 -header -csv $DB_PATH "SELECT * FROM traffic_metrics ORDER BY timestamp DESC LIMIT 60;" > $LOG_DIR/traffic_metrics.csv
    
    # Permissions Fix: Ensure these are readable/writable for git
    chmod 666 $LOG_DIR/*.csv

    echo "[$(date +%H:%M:%S)] ?? Step 4: Pushing to Dashboard..."
    
    # FIX 4: Add a small delay to prevent "unstable object" errors during file writes
    git add $LOG_DIR/*.csv
    sleep 1 
    
    # Commit with a timestamped message
    git commit -m "Nexus-Pulse: $(date +%H:%M:%S)" > /dev/null 2>&1
    
    # Final Push to update the Cloud UI
    if git push origin main; then
        echo "[$(date +%H:%M:%S)] ? Cycle Complete. Dashboard Updated."
    else
        echo "[!] WARNING: Push failed. Check internet connection/credentials."
    fi

    echo "[*] Sleeping for 20 seconds..."
    sleep 20
done