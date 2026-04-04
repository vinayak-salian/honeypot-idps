#!/bin/bash
echo "[!] INITIATING SHUTDOWN SEQUENCE..."

# 1. Stop the Sentry processes
tmux kill-session -t sentry_hunt
sudo pkill -f vulnerable_server.py
echo "[-] Traffic Capture: OFFLINE"

# 2. Stop the Scanner
sudo systemctl stop sentry-scanner.service
echo "[-] Network Census: OFFLINE"

echo "[?] All Sentry Nodes standing down."
