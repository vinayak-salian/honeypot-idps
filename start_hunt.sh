#!/bin/bash
echo "[*] IGNITING NEXUS SENTRY CORE..."

# 1. Start the Scanner Service (Census)
sudo systemctl start sentry-scanner.service
echo "[+] Network Census: ACTIVE"

# 2. Start the Main Sentry (ML Capture) in the background
# We use tmux so it keeps running after you close your laptop
tmux kill-session -t sentry_hunt 2>/dev/null
tmux new-session -d -s sentry_hunt "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/main_sentry.py"
echo "[+] ML Dispatcher: ACTIVE (Background)"

# 3. Initial Cloud Sync
/home/vinayak/honeypot_project/sync_to_cloud.sh
echo "[?] Deployment Complete. Dashboard Synchronized."
