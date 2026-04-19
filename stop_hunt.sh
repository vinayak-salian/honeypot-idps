#!/bin/bash
# Nexus Sentry: Surgical Stop Utility v5.0

echo "[*] SHUTTING DOWN NEXUS SENTRY CORE..."

# 1. Kill the background tmux session (Main Sentry)
tmux kill-session -t sentry_hunt 2>/dev/null
echo "[+] Background TMUX session terminated."

# 2. Kill all Python processes related to the project (Sudo required)
sudo pkill -9 -f "main_sentry.py"
sudo pkill -9 -f "portscan_detector.py"
sudo pkill -9 -f "python.*honeypot_project"
sudo pkill -9 -f "vulnerable_server.py"
echo "[+] Python detection engines stopped."

# 3. Kill the sync loop
pkill -f "sync_to_cloud.sh"
echo "[+] Cloud Sync loop stopped."

# 4. Clean up any Git locks
rm -f /home/vinayak/honeypot_project/.git/index.lock
echo "[+] Git locks cleared."

echo "------------------------------------------------"
echo "[!] NEXUS SENTRY IS NOW OFFLINE."
