#!/bin/bash
echo "[*] Initializing Nexus Sentry Deployment..."

# 1. Start the Network Census Service
sudo systemctl start sentry-scanner.service
echo "[+] Network Census Scanner: ACTIVE"

# 2. Start the Main Sentry in the background (detached tmux)
tmux kill-session -t sentry_hunt 2>/dev/null
tmux new-session -d -s sentry_hunt "sudo /home/vinayak/honeypot_project/venv/bin/python /home/vinayak/honeypot_project/main_sentry.py"
echo "[+] Main Sentry (ML Dispatcher): ACTIVE (tmux)"

# 3. Run initial sync to verify cloud link
/home/vinayak/honeypot_project/sync_to_cloud.sh
echo "[?] Deployment Complete. Dashboard updated."
