# Comprehensive-Network-Traffic-Monitoring-System
This system will track the network traffic of all devices on your local network, categorize it based on the types of packets (e.g., HTTP, FTP, etc.), and log usage information in real-time.
import scapy.all as scapy
import time
import logging
from collections import defaultdict

# Configuration
NETWORK_INTERFACE = "eth0"  # Set your network interface (for example, 'eth0' for Ethernet)
LOG_FILE = "network_usage.log"  # Log file for tracking traffic

# Setting up logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

# Dictionary to store data usage for each IP
data_usage = defaultdict(lambda: {'bytes_in': 0, 'bytes_out': 0})

# Function to capture packets and categorize traffic
def packet_handler(packet):
    try:
        # Check if packet has IP layer and capture the IP and packet size
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dest_ip = packet[scapy.IP].dst
            packet_size = len(packet)

            # Track incoming and outgoing traffic
            if packet[scapy.IP].src == src_ip:
                data_usage[src_ip]['bytes_out'] += packet_size
            if packet[scapy.IP].dst == dest_ip:
                data_usage[dest_ip]['bytes_in'] += packet_size

            # Log the packet information
            logging.info(f"Source: {src_ip}, Destination: {dest_ip}, Size: {packet_size} bytes")

            # Optionally categorize traffic based on protocol (HTTP, FTP, etc.)
            if packet.haslayer(scapy.TCP):
                if packet.haslayer(scapy.Raw):
                    data = packet[scapy.Raw].load
                    if b"HTTP" in data:
                        logging.info(f"HTTP traffic: {src_ip} -> {dest_ip}")
                    elif b"FTP" in data:
                        logging.info(f"FTP traffic: {src_ip} -> {dest_ip}")
    except Exception as e:
        logging.error(f"Error processing packet: {e}")

# Function to display network usage summary
def display_usage():
    print("Network Traffic Summary:")
    print("-" * 50)
    for ip, usage in data_usage.items():
        print(f"IP Address: {ip}")
        print(f"  - Incoming Traffic: {usage['bytes_in'] / (1024 * 1024):.2f} MB")
        print(f"  - Outgoing Traffic: {usage['bytes_out'] / (1024 * 1024):.2f} MB")
        print("-" * 50)

# Function to start the packet sniffing
def start_sniffing():
    print("Starting network traffic monitoring...")
    scapy.sniff(iface=NETWORK_INTERFACE, prn=packet_handler, store=0)

# Run the monitoring system in a separate thread
def run_monitoring():
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

    while True:
        time.sleep(60)  # Display usage every 60 seconds
        display_usage()

# Main execution
if __name__ == "__main__":
    run_monitoring()
