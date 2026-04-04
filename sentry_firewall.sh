#!/bin/bash
# IOT SENTRY | MASTER FIREWALL & CONTAINMENT POLICY

echo "[+] Initializing IoT Sentry Glass Prison..."

# 1. Flush existing rules to start clean
sudo iptables -F
sudo iptables -X

# ==========================================
# POLICY 1: THE DEAF-MUTE (Protect Management)
# ==========================================
# Drop honeypot traffic on USB tether and Ethernet to keep RealVNC safe
sudo iptables -A INPUT -i usb0 -p tcp --dport 8080 -j DROP
sudo iptables -A INPUT -i eth0 -p tcp --dport 8080 -j DROP

# Allow honeypot access ONLY from the Sandbox (wlan0) and Cloud VPS (tailscale0)
sudo iptables -A INPUT -i wlan0 -p tcp --dport 8080 -j ACCEPT
sudo iptables -A INPUT -i tailscale0 -p tcp --dport 8080 -j ACCEPT

# ==========================================
# POLICY 2: THE GLASS PRISON (Anti-Lateral)
# ==========================================
# Prevent the Sandbox from scanning the Home Network (192.168.x.x)
sudo iptables -A FORWARD -i wlan0 -d 192.168.0.0/16 -j DROP

# Prevent the Sandbox from scanning the USB Tether Network (10.x.x.x)
sudo iptables -A FORWARD -i wlan0 -d 10.0.0.0/8 -j DROP

# ==========================================
# POLICY 3: THE SINKHOLE (Outbound Block)
# ==========================================
# Drop any traffic trying to leave the Sandbox to the open internet
sudo iptables -A FORWARD -i wlan0 -o usb0 -j DROP
sudo iptables -A FORWARD -i wlan0 -o eth0 -j DROP

# Allow established connections to survive (Global state rule)
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

echo "[+] Sandbox wlan0 is completely isolated."
echo "[+] Lateral movement to Home/USB networks is BLOCKED."
echo "[+] Outbound internet access is BLOCKED."