#!/bin/bash
echo "[*] IGNITING NEXUS SENTRY CORE..."

# Nexus Dynamic Scanner v1.1

# 1. Extract the first 3 octets of the wlan0 IP (e.g., 10.42.0)
TARGET_PREFIX=$(ip -o -f inet addr show wlan0 | awk '{print $4}' | cut -d. -f1-3)
TARGET_RANGE="${TARGET_PREFIX}.0/24"

echo "[*] Sentry Mode: Hotspot Detected!"
echo "[!] Targeting Subnet: $TARGET_RANGE"

# 2. Launch Net Sentinel targeting the dynamic range
# (Make sure your net_sentinel.py script accepts a --target argument)
python3 net_sentinel.py --target $TARGET_RANGE

# 3. Start the Scanner Service (Census)
sudo systemctl start sentry-scanner.service
echo "[+] Network Census: ACTIVE"

# 4. Start the Main Sentry (ML Capture) in the background
# We use tmux so it keeps running after you close your laptop
tmux kill-session -t sentry_hunt 2>/dev/null
tmux new-session -d -s sentry_hunt "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/main_sentry.py"
echo "[+] ML Dispatcher: ACTIVE (Background)"

# 5. Initial Cloud Sync
/home/vinayak/honeypot_project/sync_to_cloud.sh
echo "[?] Deployment Complete. Dashboard Synchronized."
