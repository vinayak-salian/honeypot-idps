#!/bin/bash
# Nexus Sentry: Master Orchestrator v7.0
# STATUS: Full Integration (Local ARP + Global Tunnel + Cloud Sync)

echo "[*] IGNITING NEXUS SENTRY CORE..."

# 1. EMERGENCY GIT REPAIR & SYNC
# Ensures the local Pi is aligned with the latest model/code updates on GitHub
rm -f /home/vinayak/honeypot_project/.git/index.lock
git fetch origin
git reset --soft origin/main

# 2. --- THE SURGICAL WIPE ---
DB_PATH="/home/vinayak/honeypot_project/nexus_security.db"

echo "[*] Cleaning Local Noise..."
# Removes local test logs (10.42.0.x) to keep the dashboard clean for the demo
# Preserves the Global Botnet data (ips that aren't local)
sqlite3 $DB_PATH "DELETE FROM attack_logs WHERE source_ip LIKE '10.42.0.%' AND timestamp < datetime('now', '-1 hour');"

# Re-insert Gateway manually to ensure the map always shows the router
GATEWAY_IP="10.42.0.1"
GATEWAY_MAC="2c:cf:67:6c:72:6c" 
sqlite3 $DB_PATH "INSERT OR REPLACE INTO known_devices (ip_address, mac_address, last_seen) VALUES ('$GATEWAY_IP', '$GATEWAY_MAC', datetime('now', 'localtime'));"

echo "[+] Local Assets/Logs cleared. Global Botnet history preserved."

# 3. Dynamic IP Extraction
TARGET_PREFIX=$(ip -o -f inet addr show wlan0 | awk '{print $4}' | cut -d. -f1-3)
TARGET_RANGE="${TARGET_PREFIX}.0/24"

# 4. HIGH-ACCURACY ASSET DISCOVERY (99% ACCURACY)
echo "[*] Running Deep ARP Discovery on $TARGET_RANGE..."
# Requires: sudo apt-get install arp-scan
sudo arp-scan --interface=wlan0 --localnet | grep -E '([a-f0-9]{2}:){5}[a-f0-9]{2}' | while read -r line; do
    IP=$(echo $line | awk '{print $1}')
    MAC=$(echo $line | awk '{print $2}')
    sqlite3 $DB_PATH "INSERT OR REPLACE INTO known_devices (ip_address, mac_address, last_seen) VALUES ('$IP', '$MAC', datetime('now', 'localtime'));"
done
echo "[+] Discovery Complete. Local assets mapped."

# 5. KILL OLD SESSIONS & ZOMBIES
# Ensures a clean start without "Database Locked" errors
echo "[*] Cleaning environment..."
tmux kill-session -t sentry_hunt 2>/dev/null
sudo pkill -9 -f "main_sentry.py"
sudo pkill -9 -f "bruteforce_detector.py"
sudo pkill -9 -f "vulnerable_server.py"
sudo pkill -9 -f "dns_detector.py"
sudo pkill -9 -f "portscan_detector.py"
sudo pkill -9 -f "python.*honeypot_project"

# 6. LAUNCH ENGINES (Unified TMUX Orchestration)
echo "[*] Launching Engines in TMUX session: 'sentry_hunt'..."

# Create session and launch main sentry
tmux new-session -d -s sentry_hunt -n "Main" "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/main_sentry.py"

# Window 1: Brute Force Detector
tmux new-window -t sentry_hunt:1 -n "BruteForce" "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/attacks/bruteforce/bruteforce_detector.py"

# Window 2: Malware / Vulnerable Server
tmux new-window -t sentry_hunt:2 -n "VulnServer" "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/vulnerable_server.py"

# Window 3: DNS Tunnel Detector
tmux new-window -t sentry_hunt:3 -n "DNS" "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/attacks/dns/dns_detector.py"

# Window 4: PortScan Detector (Global + Local)
tmux new-window -t sentry_hunt:4 -n "PortScan" "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/attacks/portscan/portscan_detector.py"

# Window 5: Maintenance / Cloud Sync Log
tmux new-window -t sentry_hunt:5 -n "CloudSync" "watch -n 60 /home/vinayak/honeypot_project/sync_to_cloud.sh"
 
# Window 6: Active Mitigator (IPS)
tmux new-window -t sentry_hunt:6 -n "Mitigator" "while true; do sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/mitigator.py; sleep 5; done"

echo "[?] ALL ENGINES ACTIVE."
echo "[?] Monitoring Hint: Run 'tmux attach -t sentry_hunt' to see live alerts."

# Trigger Initial Sync to Cloud
/home/vinayak/honeypot_project/sync_to_cloud.sh
