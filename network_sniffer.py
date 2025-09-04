"""
Basic Network Sniffer
---------------------
Author: Your Name
Purpose: Internship Demo Project
Description:
    This program captures network packets using Scapy and
    displays useful information such as source/destination IPs,
    protocols, and payloads.

⚠️ Disclaimer:
    This project is for educational/demo purposes only.
    Please run it responsibly and only on networks you own
    or have explicit permission to test.
"""

from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    """Callback function to process each captured packet."""
    if IP in packet:
        ip_layer = packet[IP]
        print("\n[+] New Packet Captured")
        print(f"    Source IP      : {ip_layer.src}")
        print(f"    Destination IP : {ip_layer.dst}")
        print(f"    Protocol       : {ip_layer.proto}")

        # Check if it's TCP or UDP for ports
        if TCP in packet:
            print(f"    TCP Src Port   : {packet[TCP].sport}")
            print(f"    TCP Dst Port   : {packet[TCP].dport}")
        elif UDP in packet:
            print(f"    UDP Src Port   : {packet[UDP].sport}")
            print(f"    UDP Dst Port   : {packet[UDP].dport}")

        # Print raw payload if available
        if packet.haslayer("Raw"):
            payload = bytes(packet["Raw"].load)
            print(f"    Payload (first 50 bytes): {payload[:50]}")
    else:
        print("\n[!] Non-IP Packet Captured")


def main():
    print("=== Basic Network Sniffer ===")
    print("Press CTRL+C to stop...\n")

    # Start sniffing (default: all interfaces)
    sniff(prn=packet_callback, store=False)


if __name__ == "__main__":
    main()
