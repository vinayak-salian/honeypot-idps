import psutil
import csv
import os
from datetime import datetime
import subprocess
import pytz

# Path to your project logs
LOG_DIR = "/home/vinayak/honeypot_project/logs"
STATUS_FILE = os.path.join(LOG_DIR, "system_status.csv")

def get_cpu_temp():
    try:
        res = subprocess.check_output(['vcgencmd', 'measure_temp']).decode('utf-8')
        return res.replace('temp=', '').replace("'C\n", "")
    except:
        return "0.0"

def get_uptime():
    try:
        # Simplifies "up 2 hours, 30 minutes" to "2h 30m" for the dashboard card
        uptime = subprocess.check_output(['uptime', '-p']).decode('utf-8').strip()
        uptime = uptime.replace("up ", "").replace(" hours", "h").replace(" hour", "h")
        uptime = uptime.replace(" minutes", "m").replace(" minute", "m")
        return uptime
    except:
        return "Unknown"

def collect_metrics():
    # Use local time (IST) so it matches your Pi's system clock
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    cpu_temp = get_cpu_temp()
    ram_usage = psutil.virtual_memory().percent
    uptime = get_uptime()
    
    file_exists = os.path.isfile(STATUS_FILE)
    with open(STATUS_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "cpu_temp", "ram_usage", "uptime"])
        writer.writerow([timestamp, cpu_temp, ram_usage, uptime])

if __name__ == "__main__":
    collect_metrics()
