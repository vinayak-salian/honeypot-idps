#!/bin/bash
echo "[*] IGNITING NEXUS SENTRY CORE..."

# Clean the logs before starting - ensuring we have clean headers
echo "timestamp,source_ip,attack_type,target_port,protocol,confidence,evidence,latitude,longitude,country,city" > logs/security_events.csv
echo "mac_address,ip_address,last_seen" > logs/known_devices.csv

# 1. Dynamic IP Extraction
TARGET_PREFIX=$(ip -o -f inet addr show wlan0 | awk '{print $4}' | cut -d. -f1-3)
TARGET_RANGE="${TARGET_PREFIX}.0/24"

echo "[*] Sentry Mode: Hotspot Detected!"
echo "[!] Targeting Subnet: $TARGET_RANGE"

# 2. Net Sentinel (Discovery Scan)
python3 net_sentinel.py --target $TARGET_RANGE

# 3. Census Service
sudo systemctl start sentry-scanner.service
echo "[+] Network Census: ACTIVE"

# 4. Main Sentry (ML Capture) in Background
tmux kill-session -t sentry_hunt 2>/dev/null
tmux new-session -d -s sentry_hunt "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/main_sentry.py"
echo "[+] ML Dispatcher: ACTIVE (Background tmux)"

# 5. Start the Sync Loop
# Note: This will take over the current terminal so you can see the sync progress
/home/vinayak/honeypot_project/sync_to_cloud.sh
