import socket
import csv
from datetime import datetime
import os

# Path to your project logs
LOG_FILE = "/home/vinayak/honeypot_project/logs/security_events.csv"

def log_event(ip):
    # This function adds the hit to your dashboard's data source
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # We label this as 'BruteForce_Attempt' to trigger the dashboard's logic
    data = [timestamp, ip, "SSH_BruteForce_Attempt", 22, "TCP", 0.95, 19.076, 72.877, "India", "Mumbai"]
    
    file_exists = os.path.isfile(LOG_FILE)
    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        # Add header if file is new
        if not file_exists:
            writer.writerow(["timestamp", "source_ip", "attack_type", "target_port", "protocol", "confidence", "latitude", "longitude", "country", "city"])
        writer.writerow(data)

def start_bait():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 22))
    server.listen(10)
    print("[*] Sentry Bait Active & Logging. Waiting for sharks...")
    
    while True:
        try:
            client, addr = server.accept()
            # Send the "Old" banner
            vulnerable_banner = b"SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2\r\n"
            client.send(vulnerable_banner)
            
            # LOG THE HIT FOR THE DASHBOARD
            log_event(addr[0])
            print(f"[!] SHARK ATTACK! Connection logged from: {addr[0]}")
            
            client.close()
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    start_bait()
