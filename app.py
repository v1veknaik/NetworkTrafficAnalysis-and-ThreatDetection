import streamlit as st
import plotly.express as px
from sniffer import start_sniffing
from intrusion_detection import detect_intrusion

# Streamlit Page Configuration
st.set_page_config(page_title="Packet Sniffer & IDS", layout="wide")

# Page Title
st.title("🚀 Packet Sniffer & Intrusion Detection System")

# Sidebar for user input
st.sidebar.header("Settings")
packet_count = st.sidebar.slider("Number of Packets to Capture", 10, 100, 50)

# Packet Filters
st.sidebar.subheader("Packet Filters")
filter_tcp = st.sidebar.checkbox("TCP", True)
filter_udp = st.sidebar.checkbox("UDP", True)
filter_icmp = st.sidebar.checkbox("ICMP", True)
filter_dns = st.sidebar.checkbox("DNS", False)
filter_http = st.sidebar.checkbox("HTTP", False)

filters = {
    "TCP": filter_tcp,
    "UDP": filter_udp,
    "ICMP": filter_icmp,
    "DNS": filter_dns,
    "HTTP": filter_http,
}

# Button to start sniffing
if st.sidebar.button("Start Sniffing"):
    st.sidebar.success("Sniffing Started... Please wait!")

    # Capture packets
    packets = start_sniffing(packet_count, filters)

    # Display captured packets
    st.subheader("📡 Captured Packets")
    st.text_area("Packet Data", "\n".join(packets), height=300)

    # Detect intrusions & generate graph data
    alerts, ip_df, protocol_df = detect_intrusion(packets)

    # Display intrusion alerts
    if alerts:
        st.subheader("🚨 Intrusion Alerts")
        st.error("\n".join(alerts))
    else:
        st.success("✅ No suspicious activity detected.")

    # Display packet analysis graphs
    if not ip_df.empty:
        st.subheader("📊 Traffic Analysis")

        # IP Activity Graph
        fig_ip = px.bar(ip_df, x="IP Address", y="Packet Count", title="Packet Count by IP", color="Packet Count")
        st.plotly_chart(fig_ip)

        # Protocol Usage Graph
        fig_protocol = px.pie(protocol_df, names="Protocol", values="Packet Count", title="Packet Distribution by Protocol")
        st.plotly_chart(fig_protocol)
