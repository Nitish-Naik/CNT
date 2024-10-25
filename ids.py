from scapy.all import *
import logging

# Set up logging
logging.basicConfig(filename='ids_alerts.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def packet_callback(packet):
    # Detect ICMP packets
    if packet.haslayer(ICMP):
        logging.info(f"ICMP Packet Detected: {packet.summary()}")
        print(f"ICMP Packet Detected: {packet.summary()}")
        
    # Add more detection rules as needed
    # Example: Detecting SYN packets
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        logging.info(f"SYN Packet Detected: {packet.summary()}")
        print(f"SYN Packet Detected: {packet.summary()}")

def main():
    print("Starting IDS... Press CTRL+C to stop.")
    try:
        # Sniff packets and call the callback function
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("Stopping IDS...")
        exit()

if __name__ == "__main__":
    main()
