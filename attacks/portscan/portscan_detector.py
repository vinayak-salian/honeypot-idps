from scapy.all import sniff, TCP, IP, Ether
from datetime import datetime
from collections import defaultdict
import os, time, traceback

# Configuration
BASE_DIR = os.path.expanduser("/home/vinayak/honeypot_project")
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(BASE_DIR, "logs/portscan_log.csv")
os.makedirs(LOG_DIR, exist_ok=True)

# Feature Tracking
scan_tracker = defaultdict(set) # Using set for O(1) uniqueness and memory efficiency
packet_counter = defaultdict(int)
first_seen = {}

TIME_WINDOW = 5
PORT_THRESHOLD = 5
last_cleanup = time.time()

def initialize_log():
    """Creates the CSV header if the file is new."""
    if not os.path.exists(LOG_FILE):
        header = "timestamp,src_ip,mac,scan_type,unique_ports,packet_count,speed,window,iface,label\n"
        with open(LOG_FILE, "w") as f:
            f.write(header)

def get_scan_type(flags):
    """Detects scan type based on TCP Flag combinations."""
    f_str = str(flags)
    if f_str == "S": return "SYN"
    if f_str == "F": return "FIN"
    if f_str == "" or f_str == "0": return "NULL"
    # XMAS: Fin, Push, and Urg flags set
    if all(c in f_str for c in ["F", "P", "U"]): return "XMAS"
    return "OTHER"

def safe_log_write(line):
    try:
        with open(LOG_FILE, "a", buffering=1) as f:
            f.write(line + "\n")
            f.flush()
        print(f"[+] LOGGED: {line.split(',')[1]} -> {line.split(',')[4]} ports")
    except Exception:
        print(f"[-] LOG ERROR: {traceback.format_exc()}")

def detect_scan(packet):
    global last_cleanup

    # Only process TCP over IP
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        iface = packet.sniffed_on if hasattr(packet, "sniffed_on") else "any"
        
        # Capture MAC directly from the link layer (No subprocess needed!)
        mac = packet[Ether].src if Ether in packet else "Unknown"

        # Update Tracking
        if src_ip not in first_seen:
            first_seen[src_ip] = time.time()
        
        packet_counter[src_ip] += 1
        scan_tracker[src_ip].add(dst_port)

        # Check Window
        current_time = time.time()
        if current_time - last_cleanup >= TIME_WINDOW:
            process_logs(current_time)
            last_cleanup = current_time

def process_logs(current_time):
    """Processes the tracked data and writes to CSV."""
    # Iterating over copy of keys to allow deletion
    for ip in list(scan_tracker.keys()):
        unique_ports = scan_tracker[ip]
        num_unique = len(unique_ports)

        if num_unique >= PORT_THRESHOLD:
            duration = current_time - first_seen.get(ip, current_time)
            
            # Categorize Speed
            if duration < 2: speed = "fast"
            elif duration < 10: speed = "medium"
            else: speed = "slow"

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Generate CSV line (Label is 'Port_Scan' for ML training)
            log_line = (f"{timestamp},{ip},{mac},OTHER,{num_unique},"
                        f"{packet_counter[ip]},{speed},{TIME_WINDOW},any,Port_Scan")
            
            safe_log_write(log_line)

        # Flush tracking for this IP to prepare for next window
        del scan_tracker[ip]
        del packet_counter[ip]
        del first_seen[ip]

if __name__ == "__main__":
    initialize_log()
    
    # Define which interface faces the 'outside' world
    # On a Pi, this is usually eth0 (built-in ethernet)
    TARGET_INTERFACE = "eth0" 

    print(f"[*] Net Sentinel: Sentry Mode Active on {TARGET_INTERFACE}...")
    
    # Added 'iface' parameter to lock sniffing to the entry point
    sniff(iface=TARGET_INTERFACE, filter="tcp", prn=detect_scan, store=0)
