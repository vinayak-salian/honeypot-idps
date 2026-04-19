#!/bin/bash
# Nexus Sentry: Master Orchestrator v6.3
# LOGIC: Nukes local demo noise, preserves global botnets, and SYNC TO CLOUD.

echo "[*] IGNITING NEXUS SENTRY CORE..."

# 1. EMERGENCY GIT REPAIR
rm -f /home/vinayak/honeypot_project/.git/index.lock
git fetch origin
git reset --soft origin/main

# 2. --- THE REAL SURGICAL WIPE ---
DB_PATH="/home/vinayak/honeypot_project/nexus_security.db"

echo "[*] Nuking Stale Local Logs & Resetting Assets..."
# Deletes by IP range to catch any old India/Mumbai hardcoded entries
sqlite3 $DB_PATH "DELETE FROM attack_logs WHERE source_ip LIKE '10.42.0.%' OR source_ip LIKE '192.168.%' OR source_ip = '127.0.0.1';"
sqlite3 $DB_PATH "DELETE FROM known_devices;"

# Re-insert Gateway manually so the asset map isn't empty
GATEWAY_IP="10.42.0.1"
GATEWAY_MAC="2c:cf:67:6c:72:6c" 
sqlite3 $DB_PATH "INSERT INTO known_devices (ip_address, mac_address, last_seen) VALUES ('$GATEWAY_IP', '$GATEWAY_MAC', datetime('now'));"

echo "[+] Local Assets/Logs cleared. Global Botnet history preserved."

# 3. Dynamic IP Extraction
TARGET_PREFIX=$(ip -o -f inet addr show wlan0 | awk '{print $4}' | cut -d. -f1-3)
TARGET_RANGE="${TARGET_PREFIX}.0/24"

# 4. Active Discovery
echo "[*] Running Deep ARP Discovery..."
sudo nmap -sn -PR $TARGET_RANGE > /dev/null

# 5. KILL OLD SESSIONS & ZOMBIES
echo "[*] Cleaning environment..."
tmux kill-session -t sentry_hunt 2>/dev/null
sudo pkill -9 -f "main_sentry.py"
sudo pkill -9 -f "bruteforce_detector.py"
sudo pkill -9 -f "vulnerable_server.py"
sudo pkill -9 -f "dns_detector.py"
sudo pkill -9 -f "portscan_detector.py"
sudo pkill -9 -f "python.*honeypot_project"

# 6. START ENGINES
echo "[*] Launching All 4 Engines..."
tmux new-session -d -s sentry_hunt "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/main_sentry.py"
tmux new-window -t sentry_hunt:1 "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/attacks/bruteforce/bruteforce_detector.py"
tmux new-window -t sentry_hunt:2 "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/attacks/malware/vulnerable_server.py"
tmux new-window -t sentry_hunt:3 "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/attacks/dns/dns_detector.py"
tmux new-window -t sentry_hunt:4 "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/attacks/portscan/portscan_detector.py"

echo "[?] All Engines ACTIVE. Pushing state to Streamlit Cloud..."
# --- THE SYNC: This is what makes your Cloud Dashboard update ---
/home/vinayak/honeypot_project/sync_to_cloud.sh
