#!/bin/bash
# Nexus Sentry: Professional Demo Reset v5.0
# Optimized for SIES GST Live Demo 

LOG_DIR="/home/vinayak/honeypot_project/logs"
DB_PATH="/home/vinayak/honeypot_project/nexus_security.db"

echo "[*] NEXUS SENTRY: INITIATING NUCLEAR RESET..."

# 1. CLEAN THE DATABASE (Stops old data from coming back)
# We delete the rows so the tables remain intact
sqlite3 $DB_PATH "DELETE FROM attack_logs;"
sqlite3 $DB_PATH "DELETE FROM banned_ips;"
sqlite3 $DB_PATH "DELETE FROM known_devices;"
sqlite3 $DB_PATH "DELETE FROM traffic_metrics;"
sqlite3 $DB_PATH "DELETE FROM web_history;"
echo "[+] SQLite Database: PURGED"

# 2. FLUSH FIREWALL (Releases all blocked devices instantly)
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
# Re-enable forwarding just in case
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
echo "[+] IPTables: FLUSHED (All network blocks lifted)"

# 3. RESET CSV LOGS WITH HEADERS (Matches Dashboard logic exactly)
# Added 'evidence' to security_events and included the missing CSVs
echo "timestamp,source_ip,attack_type,target_port,protocol,confidence,evidence,latitude,longitude,country,city" > $LOG_DIR/security_events.csv
echo "mac_address,ip_address,last_seen" > $LOG_DIR/known_devices.csv
echo "timestamp,cpu_temp,ram_usage,uptime,gateway_ip" > $LOG_DIR/system_status.csv
echo "Banned IP,Timestamp,Reason" > $LOG_DIR/banned_ips.csv
echo "timestamp,source_ip,domain" > $LOG_DIR/web_history.csv
echo "timestamp,tcp_count,udp_count,icmp_count,total_bytes" > $LOG_DIR/traffic_metrics.csv
echo "timestamp,ip,action" > $LOG_DIR/action_queue.csv

# Ensure permissions are correct for the sync script
chmod 666 $LOG_DIR/*.csv
echo "[+] CSV Logs: REINITIALIZED"

# 4. PUSH CLEAN STATE TO GITHUB
# This clears the dashboard IMMEDIATELY so you don't have to wait
cd /home/vinayak/honeypot_project/
git add logs/*.csv
git commit -m "Demo-Reset: System Purge" > /dev/null 2>&1
git push origin main > /dev/null 2>&1
echo "[+] Cloud Dashboard: CLEARED"

echo "------------------------------------------------"
echo "[!] NEXUS SENTRY: READY FOR LIVE DEMO."
