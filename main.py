import scapy.all as scapy

def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print(f"\n[+] New Packet: {ip_src} to {ip_dst}, Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            print(f"    TCP Source Port: {src_port}, TCP Destination Port: {dst_port}")

        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            print(f"    UDP Source Port: {src_port}, UDP Destination Port: {dst_port}")

        elif packet.haslayer(scapy.ICMP):
            icmp_type = packet[scapy.ICMP].type
            icmp_code = packet[scapy.ICMP].code
            print(f"    ICMP Type: {icmp_type}, ICMP Code: {icmp_code}")

        else:
            print("    Other IP Packet")

# Set your network interface (e.g., "eth0" or "wlan0")
network_interface = "your_network_interface"
sniff_packets(network_interface)
