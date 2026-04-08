import psutil
import csv
import os
from datetime import datetime
import subprocess

LOG_DIR = "/home/vinayak/honeypot_project/logs"
STATUS_FILE = os.path.join(LOG_DIR, "system_status.csv")

def get_gateway_ip():
    try:
        # Check for usb0 (tethering), then wlan0 (AP), then eth0
        # This command grabs the first valid internal IP found
        cmd = "ip addr show | grep -E 'usb0|wlan0|eth0' | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -n 1"
        ip = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
        return ip if ip else "0.0.0.0"
    except:
        return "0.0.0.0"

def get_uptime_clean():
    try:
        uptime = subprocess.check_output(['uptime', '-p']).decode('utf-8').strip()
        uptime = uptime.replace("up ", "").replace(" hours", "h").replace(" hour", "h")
        uptime = uptime.replace(" minutes", "m").replace(" minute", "m").replace(",", "")
        return uptime
    except:
        return "Unknown"

def collect_metrics():
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    gateway = get_gateway_ip()
    uptime = get_uptime_clean()
    
    file_exists = os.path.isfile(STATUS_FILE)
    with open(STATUS_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "cpu_temp", "ram_usage", "uptime", "gateway_ip"])
        writer.writerow([timestamp, 0, 0, uptime, gateway])

if __name__ == "__main__":
    collect_metrics()
