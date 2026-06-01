from scapy.all import sniff, IP, Raw
from datetime import datetime

def packet_callback(packet):
    if packet.haslayer(IP):

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        protocol = packet[IP].proto

        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        elif protocol == 1:
            protocol_name = "ICMP"
        else:
            protocol_name = str(protocol)

        print("\n===== PACKET =====")
        print("Time:", timestamp)
        print("Source IP:", packet[IP].src)
        print("Destination IP:", packet[IP].dst)
        print("Protocol:", protocol_name)

        if packet.haslayer(Raw):
            print("Payload:", packet[Raw].load[:50])

print("Sniffer Started...")
sniff(prn=packet_callback, count=20)