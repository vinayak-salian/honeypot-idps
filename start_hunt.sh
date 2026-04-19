#!/bin/bash
# Nexus Sentry: Master Orchestrator v5.8
# SAFETY UPDATE: Preserves History, Resets ONLY Local Assets

echo "[*] IGNITING NEXUS SENTRY CORE..."

# 1. EMERGENCY GIT REPAIR
rm -f /home/vinayak/honeypot_project/.git/index.lock
git fetch origin
git reset --soft origin/main

# 2. --- SELECTIVE DEMO RESET ---
# We ONLY clear the local device map. We DO NOT touch attack_logs or CSVs.
DB_PATH="/home/vinayak/honeypot_project/nexus_security.db"
sqlite3 $DB_PATH "DELETE FROM known_devices;"
echo "[+] Local Asset map cleared for fresh discovery."

# 3. Dynamic IP Extraction
TARGET_PREFIX=$(ip -o -f inet addr show wlan0 | awk '{print $4}' | cut -d. -f1-3)
TARGET_RANGE="${TARGET_PREFIX}.0/24"

# 4. Active Discovery (Repopulates the 'known_devices' table)
echo "[*] Scanning for local assets..."
nmap -sn $TARGET_RANGE > /dev/null

# 5. KILL OLD SESSIONS
echo "[*] Cleaning environment..."
tmux kill-session -t sentry_hunt 2>/dev/null
sudo pkill -9 -f "main_sentry.py"
sudo pkill -9 -f "bruteforce_detector.py"
sudo pkill -9 -f "vulnerable_server.py"
sudo pkill -9 -f "dns_detector.py"
sudo pkill -9 -f "python.*honeypot_project"

# 6. START ENGINES
tmux new-session -d -s sentry_hunt "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/main_sentry.py"
tmux new-window -t sentry_hunt:1 "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/attacks/bruteforce/bruteforce_detector.py"
tmux new-window -t sentry_hunt:2 "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/vulnerable_server.py"
tmux new-window -t sentry_hunt:3 "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/attacks/dns/dns_detector.py"

echo "[?] Sentry Engines ACTIVE. History Preserved."
/home/vinayak/honeypot_project/sync_to_cloud.sh