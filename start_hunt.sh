#!/bin/bash
# Nexus Sentry v7.2 - Final Demo Stability Patch (Full Suite)

DB_PATH="/home/vinayak/honeypot_project/nexus_security.db"

echo "[*] IGNITING NEXUS SENTRY CORE..."

# 1. Clear Git Locks (Crucial for USB tethering)
rm -f /home/vinayak/honeypot_project/.git/index.lock

# 2. Surgical Wipe
echo "[*] Cleaning Local Noise..."
sqlite3 $DB_PATH "DELETE FROM attack_logs WHERE source_ip LIKE '10.42.0.%' OR source_ip LIKE '192.168.%';"
sqlite3 $DB_PATH "DELETE FROM known_devices;"

# 3. Aggressive Initial Discovery
echo "[*] Running Deep ARP Discovery on 10.42.0.0/24..."
sudo arp-scan --interface=wlan0 --localnet | grep -E '([a-f0-9]{2}:){5}[a-f0-9]{2}' | while read -r line; do
    IP=$(echo $line | awk '{print $1}')
    MAC=$(echo $line | awk '{print $2}')
    sqlite3 $DB_PATH "INSERT OR REPLACE INTO known_devices (ip_address, mac_address, last_seen) VALUES ('$IP', '$MAC', datetime('now', 'localtime'));"
done

# 4. Cleanup old processes
echo "[*] Cleaning environment..."
tmux kill-session -t sentry_hunt 2>/dev/null
sudo pkill -9 -f "python.*honeypot_project"

# 5. Launch Engines with "Stay Alive" logic
echo "[*] Launching Engines..."

# Create session
tmux new-session -d -s sentry_hunt -n "Main" "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/main_sentry.py; read"

# Window 1: Continuous Census (Discovery)
tmux new-window -t sentry_hunt:1 -n "Census" "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/network_census.py; read"

# Window 2: Brute Force
tmux new-window -t sentry_hunt:2 -n "Brute" "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/attacks/bruteforce/bruteforce_detector.py; read"

# Window 3: PortScan
tmux new-window -t sentry_hunt:3 -n "Scan" "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/attacks/portscan/portscan_detector.py; read"

# Window 4: DNS
tmux new-window -t sentry_hunt:4 -n "DNS" "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/attacks/dns/dns_detector.py; read"

# Window 5: Cloud Sync (Background Loop)
tmux new-window -t sentry_hunt:5 -n "Sync" "while true; do /home/vinayak/honeypot_project/sync_to_cloud.sh; sleep 60; done"

# Window 6: Vulnerable Server (Malware Delivery Honeypot)
tmux new-window -t sentry_hunt:6 -n "Malware" "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/vulnerable_server.py; read"

# Window 7: Active Mitigator (IPS Action Engine)
tmux new-window -t sentry_hunt:7 -n "Mitigate" "while true; do sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/mitigator.py; sleep 5; done"

echo "[?] ALL ENGINES INITIALIZED."
echo "[*] Run 'tmux attach -t sentry_hunt' to monitor the system."
