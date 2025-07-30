from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw
import logging

# Configure logging
logging.basicConfig(filename="log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

# Function to process packets based on filters
def packet_callback(packet, filters):
    packet_info = ""

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if filters.get("TCP") and packet.haslayer(TCP):
            packet_info = f"Source: {src_ip} -> Destination: {dst_ip} | TCP | Src Port: {packet[TCP].sport}, Dst Port: {packet[TCP].dport}"
        elif filters.get("UDP") and packet.haslayer(UDP):
            packet_info = f"Source: {src_ip} -> Destination: {dst_ip} | UDP | Src Port: {packet[UDP].sport}, Dst Port: {packet[UDP].dport}"
        elif filters.get("ICMP") and packet.haslayer(ICMP):
            packet_info = f"Source: {src_ip} -> Destination: {dst_ip} | ICMP Packet Detected"
        elif filters.get("DNS") and packet.haslayer(DNS):
            packet_info = f"Source: {src_ip} -> Destination: {dst_ip} | DNS Query Detected"
        elif filters.get("HTTP") and packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors="ignore")
            if "HTTP" in payload:
                packet_info = f"Source: {src_ip} -> Destination: {dst_ip} | HTTP Data: {payload[:50]}..."  # Show first 50 chars

        if packet_info:
            logging.info(packet_info)
            return packet_info  # Return packet details for UI

# Function to start sniffing
def start_sniffing(packet_count=50, filters=None):
    if filters is None:
        filters = {"TCP": True, "UDP": True, "ICMP": True, "DNS": False, "HTTP": False}  # Default

    packets = []

    def callback(packet):
        packet_info = packet_callback(packet, filters)
        if packet_info:
            packets.append(packet_info)

    sniff(prn=callback, store=False, count=packet_count)  # Capture packets
    return packets  # Return captured packets for UI
