from scapy.all import sniff, TCP, IP
import datetime

# Logging and alert system
def alert(msg):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[ALERT] {timestamp} - {msg}"
    print(log_msg)
    with open("alert_log.txt", "a") as f:
        f.write(log_msg + "\n")

# Analyze incoming packets
def analyze_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        sport = packet[TCP].sport            # Source port
        dport = packet[TCP].dport            # Destination port
        src_ip = packet[IP].src              # Source IP address
        dst_ip = packet[IP].dst              # Destination IP address
        flags = packet[TCP].flags            # TCP flags (SYN, FIN, etc.)

        # ✅ Ignore packets coming from your own IP address
        if src_ip == "192.168.29.38":
            return

        # Detect SYN packet
        if flags == "S":
            alert(f"SYN Packet Detected | Src: {src_ip} -> Dst Port: {dport}")

        # Detect XMAS scan (FIN + PSH + URG set)
        if flags == "FPU":
            alert(f"Possible XMAS Scan | Src: {src_ip} -> Dst: {dst_ip}")

# Start sniffing
def start_monitoring(interface):
    print(f"[*] Starting Intrusion Detection on {interface}...\n")
    sniff(iface=interface, prn=analyze_packet, store=0)

# Main execution
if __name__ == "__main__":
    interface = input("Enter your network interface (e.g., eth0, wlan0): ")
    start_monitoring(interface)
