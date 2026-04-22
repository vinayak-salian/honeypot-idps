#!/bin/bash
# Nexus Sentry v8.7 - Botnet Protection & Hammer Sync
 
DB_PATH="/home/vinayak/honeypot_project/nexus_security.db"
PROJECT_DIR="/home/vinayak/honeypot_project"
 
echo "[*] IGNITING NEXUS SENTRY CORE..."
 
# 1. Clear Git Locks
rm -f $PROJECT_DIR/.git/index.lock
cd $PROJECT_DIR
 
# 2. SELECTIVE WIPE (Keeps Global Botnets, Cleans Local Session)
echo "[*] Cleaning Local Session Noise..."
sqlite3 $DB_PATH "DELETE FROM attack_logs WHERE source_ip LIKE '10.42.0.%' OR source_ip LIKE '192.168.%';"
sqlite3 $DB_PATH "DELETE FROM known_devices;"
sqlite3 $DB_PATH "DELETE FROM web_history;"
 
# 3. Discovery
echo "[*] Running Deep ARP Discovery..."
sudo arp-scan --interface=wlan0 --localnet | grep -E '([a-f0-9]{2}:){5}[a-f0-9]{2}' | while read -r line; do
    IP=$(echo $line | awk '{print $1}')
    MAC=$(echo $line | awk '{print $2}')
    sqlite3 $DB_PATH "INSERT OR REPLACE INTO known_devices (ip_address, mac_address, last_seen) VALUES ('$IP', '$MAC', datetime('now', 'localtime'));"
done
 
# 4. Cleanup old processes
tmux kill-session -t sentry_hunt 2>/dev/null
sudo pkill -9 -f "python.*honeypot_project"
 
# 5. Launch Engines
tmux new-session -d -s sentry_hunt -n "Main" "sudo $PROJECT_DIR/venv/bin/python $PROJECT_DIR/main_sentry.py; read"
tmux new-window -t sentry_hunt:1 -n "Census" "sudo $PROJECT_DIR/venv/bin/python $PROJECT_DIR/network_census.py; read"
tmux new-window -t sentry_hunt:2 -n "Brute" "sudo $PROJECT_DIR/venv/bin/python $PROJECT_DIR/attacks/bruteforce/bruteforce_detector.py; read"
tmux new-window -t sentry_hunt:3 -n "Scan" "sudo $PROJECT_DIR/venv/bin/python $PROJECT_DIR/attacks/portscan/portscan_detector.py; read"
tmux new-window -t sentry_hunt:4 -n "DNS" "sudo $PROJECT_DIR/venv/bin/python $PROJECT_DIR/attacks/dns/dns_detector.py; read"
 
# WINDOW 5: CLOUD SYNC — single authoritative push, no more dual-push race
tmux new-window -t sentry_hunt:5 -n "Sync" "bash $PROJECT_DIR/sync_to_cloud.sh 2>&1 | tee -a $PROJECT_DIR/sync.log"
 
tmux new-window -t sentry_hunt:6 -n "Malware" "sudo $PROJECT_DIR/venv/bin/python $PROJECT_DIR/attacks/malware/vulnerable_server.py; read"
tmux new-window -t sentry_hunt:7 -n "Mitigate" "sudo $PROJECT_DIR/venv/bin/python $PROJECT_DIR/mitigator.py; read"
 
# WINDOW 8: SSH HONEYPOT — writes to SQLite so sync picks it up correctly
tmux new-window -t sentry_hunt:8 -n "SSH" "sudo $PROJECT_DIR/venv/bin/python $PROJECT_DIR/vulnerable_ssh.py; read"
 
echo "[?] SYSTEM STABILIZED. Dashboard turns green in 25s."
