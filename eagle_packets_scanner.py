#!/usr/bin/env python

import psutil
import scapy.all as scapy
import threading
import time
import socket
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError
from blessed import Terminal
from termcolor import colored
from tabulate import tabulate

# List to store packet data
packet_data = []
temp_packet_data = []

# Flag to control the packet sniffing
sniffing = True

# Create a terminal instance
term = Terminal()

# Lock for thread synchronization
data_lock = threading.Lock()

# Protocols supported by dpkt
protocol_names = {
    1: "ICMP",
    6: "TCP",
    7: "Echo",
    9: "Discard",
    11: "Systat",
    13: "Daytime",
    17: "UDP",
    19: "Chargen",
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    37: "Time",
    39: "RLP",
    42: "Nameserver",
    43: "NICNAME/Whois",
    47: "GRE",
    49: "TACACS",
    50: "ESP",
    51: "AH",
    53: "DNS",
    57: "MTP",
    67: "BOOTP Server",
    68: "BOOTP Client",
    69: "TFTP",
    70: "Gopher",
    79: "Finger",
    80: "HTTP",
    81: "HOSTS2 Name Server",
    88: "Kerberos",
    101: "NIC Host Name",
    102: "ISO-TSAP",
    107: "Remote Telnet Service",
    109: "POP2",
    110: "POP3",
    111: "Sun RPC",
    113: "Authentication Service",
    117: "UUCP Path Service",
    118: "SQL Services",
    119: "NNTP",
    123: "NTP",
    135: "DCE endpoint resolution",
    137: "NETBIOS Name Service",
    138: "NETBIOS Datagram Service",
    139: "NETBIOS Session Service",
    143: "IMAP",
    150: "SQLNET",
    156: "SQL Service",
    158: "PCMail Server",
    161: "SNMP",
    162: "SNMP Trap",
    170: "Network Printing Protocol",
    179: "BGP",
    194: "IRC",
    213: "IPX",
    220: "IMAP3",
    443: "HTTPS",
    546: "DHCPv6 Client",
    547: "DHCPv6 Server",
    636: "LDAP SSL",
    873: "rsync",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    1521: "Oracle SQL",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP Proxy"
}

# Function to analyze packets
def analyze_packets(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        src_status = check_ip_reputation(ip_src)
        dst_status = check_ip_reputation(ip_dst)
        protocol_number = packet[scapy.IP].proto
        protocol_name = protocol_names.get(protocol_number, "Unknown Protocol")

        with data_lock:
            temp_packet_data.append((ip_src, src_status, ip_dst, dst_status, protocol_name))

# Function to check IP reputation
def check_ip_reputation(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        if 'entities' in res:
            return "Trustworthy"
        else:
            return "Suspicious"
    except IPDefinedError:
        return "Private/Reserved"
    except Exception as e:
        return f"Unknown ({e})"

# Function to start packet sniffing
def start_packet_sniffing(interface):
    scapy.sniff(iface=interface, prn=analyze_packets, store=False, stop_filter=lambda x: not sniffing)

# Function to print combined table for network traffic and protocol analysis
def print_combined_table(term):
    global packet_data, temp_packet_data
    while sniffing:
        with data_lock:
            if temp_packet_data:
                packet_data.extend(temp_packet_data)
                temp_packet_data = []

        if packet_data:
            combined_table = []
            for src, src_status, dst, dst_status, protocol in packet_data:
                combined_table.append([src, src_status, dst, dst_status, protocol])

            with term.location():
                print(term.clear())
                print(term.orange_on_black(term.center("EPS - Eagle Packets Scanner")))
                print(term.move_y(1) + "Network Traffic and Protocol Analysis Table:")
                table_str = tabulate(combined_table, headers=["Source IP", "Source Status", "Destination IP", "Destination Status", "Protocol"])
                print(term.move_y(2) + table_str)

        time.sleep(1)  # Reduced sleep time for more frequent updates

# Main function
def main():
    try:
        # Get available network interfaces
        interfaces = psutil.net_if_addrs()
        print("Available Network Interfaces:")
        for interface_name, _ in interfaces.items():
            print(interface_name)

        # Select the interface used by the user on the device
        interface = None
        for interface_name, addresses in interfaces.items():
            for addr in addresses:
                if addr.family == socket.AF_INET:
                    interface = interface_name
                    break
            if interface:
                break

        if interface:
            print(f"Selected interface: {interface}")
        else:
            print("No suitable interface found.")
            return

        sniffing_thread = threading.Thread(target=start_packet_sniffing, args=(interface,))
        sniffing_thread.dasniffing_thread.daemon = True
        sniffing_thread.start()

        combined_thread = threading.Thread(target=print_combined_table, args=(term,))
        combined_thread.daemon = True
        combined_thread.start()

        while True:
            time.sleep(1)
            if not (sniffing_thread.is_alive() and combined_thread.is_alive()):
                break

    except KeyboardInterrupt:
        global sniffing
        sniffing = False
        print("\nStopping packet sniffing...")
        print("\nClose Eagle Packets Scanner...")

if __name__ == "__main__":
    main()

