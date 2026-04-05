import psutil
import csv
import os
from datetime import datetime
import subprocess

# Path to your project logs
LOG_DIR = "/home/vinayak/honeypot_project/logs"
STATUS_FILE = os.path.join(LOG_DIR, "system_status.csv")

def get_cpu_temp():
    try:
        # Specific to Raspberry Pi
        res = subprocess.check_output(['vcgencmd', 'measure_temp']).decode('utf-8')
        return res.replace('temp=', '').replace("'C\n", "")
    except:
        return "0.0"

def get_uptime():
    try:
        uptime = subprocess.check_output(['uptime', '-p']).decode('utf-8').strip()
        return uptime.replace("up ", "")
    except:
        return "Unknown"

def collect_metrics():
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cpu_temp = get_cpu_temp()
    ram_usage = psutil.virtual_memory().percent
    uptime = get_uptime()
    
    file_exists = os.path.isfile(STATUS_FILE)
    with open(STATUS_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "cpu_temp", "ram_usage", "uptime"])
        
        # We only keep the latest status to keep the file small, or append for history
        writer.writerow([timestamp, cpu_temp, ram_usage, uptime])

if __name__ == "__main__":
    collect_metrics()