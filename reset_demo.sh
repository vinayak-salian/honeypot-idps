#!/bin/bash
LOG_DIR="/home/vinayak/honeypot_project/logs"
echo "timestamp,source_ip,attack_type,target_port,protocol,confidence,latitude,longitude,country,city" > $LOG_DIR/security_events.csv
echo "mac_address,ip_address,last_seen" > $LOG_DIR/known_devices.csv
echo "timestamp,cpu_temp,ram_usage,uptime,gateway_ip" > $LOG_DIR/system_status.csv
echo "[!] Session Cleaned. Ready for Live Demo."