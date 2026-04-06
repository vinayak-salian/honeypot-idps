import psutil
import csv
import os
from datetime import datetime
import subprocess

LOG_DIR = "/home/vinayak/honeypot_project/logs"
STATUS_FILE = os.path.join(LOG_DIR, "system_status.csv")

def get_gateway_ip():
    try:
        # Gets the IP of the wlan0 interface (the AP interface for your demo)
        cmd = "hostname -I | awk '{print $1}'"
        return subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
    except:
        return "0.0.0.0"

def get_uptime_clean():
    try:
        # Converts "up 2 hours, 30 minutes" to "2h 30m"
        uptime = subprocess.check_output(['uptime', '-p']).decode('utf-8').strip()
        uptime = uptime.replace("up ", "").replace(" hours", "h").replace(" hour", "h")
        uptime = uptime.replace(" minutes", "m").replace(" minute", "m").replace(",", "")
        return uptime
    except:
        return "Unknown"

def collect_metrics():
    # Use local time for the SIES GST demo consistency
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    gateway = get_gateway_ip()
    uptime = get_uptime_clean()
    
    # We append for history, but the dashboard only shows the last line
    file_exists = os.path.isfile(STATUS_FILE)
    with open(STATUS_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "cpu_temp", "ram_usage", "uptime", "gateway_ip"])
        # Writing 0 for Temp/RAM since we are hiding them, but keeping the CSV structure
        writer.writerow([timestamp, 0, 0, uptime, gateway])

if __name__ == "__main__":
    collect_metrics()
