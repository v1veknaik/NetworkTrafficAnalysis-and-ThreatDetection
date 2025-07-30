import logging
from collections import defaultdict
import pandas as pd

# Configure logging
logging.basicConfig(filename="intrusion_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

# Function to detect intrusions & prepare graph data
def detect_intrusion(packets):
    ip_counts = defaultdict(int)
    protocol_counts = defaultdict(int)
    alerts = []

    for packet in packets:
        parts = packet.split("|")  # Extract details
        if "Source:" in packet:
            src_ip = parts[0].split(" ")[1]
            ip_counts[src_ip] += 1

        # Count protocols
        for proto in ["TCP", "UDP", "ICMP", "DNS", "HTTP"]:
            if proto in packet:
                protocol_counts[proto] += 1

    # Detect abnormal activities
    for ip, count in ip_counts.items():
        if count > 20:
            alert = f"🚨 Possible DDoS Attack from {ip} - {count} packets"
            logging.warning(alert)
            alerts.append(alert)

    # Convert data to Pandas DataFrame for visualization
    ip_df = pd.DataFrame(list(ip_counts.items()), columns=["IP Address", "Packet Count"])
    protocol_df = pd.DataFrame(list(protocol_counts.items()), columns=["Protocol", "Packet Count"])

    return alerts, ip_df, protocol_df  # Return alerts & graph data
