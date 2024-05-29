# packet_functions.py

import time
import scapy.all as scapy
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError
from termcolor import colored
from mac_vendor_lookup import MacLookup
import protocols

# Initialize MacLookup instance
mac_lookup = MacLookup()

# Protocols supported by dpkt
protocol_names = protocols.protocol_names

# Function to get vendor by MAC address
def get_mac_vendor(mac_address):
    try:
        vendor = mac_lookup.lookup(mac_address)
        return vendor
    except Exception:
        return "Unknown Vendor"

# Function to apply filters to packets
def apply_filters(packet, filters):
    ip_src = packet[scapy.IP].src
    ip_dst = packet[scapy.IP].dst
    protocol_number = packet[scapy.IP].proto
    protocol_name = protocol_names.get(protocol_number, "Unknown Protocol")

    if filters.get("src_ip") and filters["src_ip"] != ip_src:
        return False
    if filters.get("dst_ip") and filters["dst_ip"] != ip_dst:
        return False
    if filters.get("protocol") and filters["protocol"] != protocol_name:
        return False

    return True

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

# Function to analyze packets
def analyze_packets(packet, filters, temp_packet_data, data_lock):
    if packet.haslayer(scapy.IP):
        if not apply_filters(packet, filters):
            return

        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        src_status = check_ip_reputation(ip_src)
        dst_status = check_ip_reputation(ip_dst)
        protocol_number = packet[scapy.IP].proto
        protocol_name = protocol_names.get(protocol_number, "Unknown Protocol")
        packet_summary = packet.summary()  # Packet summary including protocol

        src_mac = dst_mac = vlan = program_name = "N/A"  # Default values

        # Check if packet has Ethernet layer
        if packet.haslayer(scapy.Ether):
            src_mac = packet[scapy.Ether].src
            dst_mac = packet[scapy.Ether].dst

            # Get vendor names for MAC addresses
            src_vendor = get_mac_vendor(src_mac)
            dst_vendor = get_mac_vendor(dst_mac)

            # Check if packet has VLAN layer
            if packet.haslayer(scapy.Dot1Q):
                vlan = packet[scapy.Dot1Q].vlan

        # Check if packet has TCP layer
        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
        else:
            src_port = dst_port = "N/A"

        packet_length = len(packet)
        packet_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))

        packet_entry = (ip_src, src_status, src_port, src_mac, src_vendor, ip_dst, dst_status, dst_port, dst_mac, dst_vendor, vlan, protocol_name, packet_summary, packet_length, packet_time, program_name)
        
        with data_lock:
            temp_packet_data.append(packet_entry)
