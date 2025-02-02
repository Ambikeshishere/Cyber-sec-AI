from scapy.all import sniff
import ipaddress


MALICIOUS_IPS = {
    "192.168.1.100",
    "203.0.113.45",
}

def check_packet(packet):
    """Analyze a network packet for suspicious activity."""
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dest_ip = packet["IP"].dst

        if src_ip in MALICIOUS_IPS or dest_ip in MALICIOUS_IPS:
            print(f"Alert: Malicious traffic detected from {src_ip} to {dest_ip}")

def start_sniffer(interface):
    """Start sniffing packets on the given network interface."""
    print(f"Starting network analyzer on interface: {interface}")
    
    sniff(iface=interface, prn=check_packet, store=0, timeout=60)  

if __name__ == "__main__":
    interface = input("Enter network interface (e.g., eth0, wlan0): ")
    start_sniffer(interface)
