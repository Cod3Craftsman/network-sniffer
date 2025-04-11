from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(IP):
        print(f"Source: {packet[IP].src} → Destination: {packet[IP].dst}")
        print(f"Protocol: {packet.proto}")
        print("Packet Info:")
        packet.show()
        print("\n")
    elif packet.haslayer(ARP):
        print("ARP Packet Detected")
        packet.show()
    else:
        print(f"Other Packet Type: {packet.summary()}")
        print("____________________________")

print("Starting to sniff network traffic ...\n")
sniff(prn=packet_callback, store=0, count=10, timeout=30)
