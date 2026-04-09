import socket
import csv
from datetime import datetime
import os

# Path to your project logs
LOG_FILE = "/home/vinayak/honeypot_project/logs/security_events.csv"

def log_event(ip):
    # This function adds the hit to your dashboard's data source
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # UPDATED: We use 'Brute_Force_SHARK_Attack' to ensure it hits your Dashboard's Tab 3 filters perfectly
    attack_label = "Brute_Force_SHARK_Attack"
    
    # Format: timestamp, source_ip, attack_type, target_port, protocol, confidence, lat, long, country, city
    data = [timestamp, ip, attack_label, 22, "TCP", 0.99, 19.076, 72.877, "India", "Mumbai"]
    
    file_exists = os.path.isfile(LOG_FILE)
    try:
        with open(LOG_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            # Add header if file is new
            if not file_exists:
                writer.writerow(["timestamp", "source_ip", "attack_type", "target_port", "protocol", "confidence", "latitude", "longitude", "country", "city"])
            writer.writerow(data)
        print(f"[+] CSV Update: {ip} recorded as {attack_label}")
    except Exception as e:
        print(f"[-] CSV Write Error: {e}")

def start_bait():
    # Binding to port 22. Ensure you run this with 'sudo'
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(('0.0.0.0', 22))
        server.listen(10)
        print("[*] Sentry Bait Active & Logging. Waiting for sharks...")
        
        while True:
            try:
                client, addr = server.accept()
                
                # Send the "Old" banner to look like a vulnerable Ubuntu 14.04 system
                vulnerable_banner = b"SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2\r\n"
                client.send(vulnerable_banner)
                
                # LOG THE HIT FOR THE DASHBOARD
                log_event(addr[0])
                print(f"[!] SHARK ATTACK! Connection logged from: {addr[0]}")
                
                client.close()
            except Exception as e:
                print(f"Error handling connection: {e}")
    except PermissionError:
        print("[-] Permission Denied: You must run this script with 'sudo' to bind to Port 22.")
    except Exception as e:
        print(f"[-] Server Error: {e}")

if __name__ == "__main__":
    start_bait()
