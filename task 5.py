from curses import raw
from telnetlib import IP
from scapy.all import * # type: ignore


def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        payload = packet[raw].load if raw in packet else None

        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}, Payload Data: {payload}")


sniff(filter="ip", prn=packet_handler, store=0)  # type: ignore