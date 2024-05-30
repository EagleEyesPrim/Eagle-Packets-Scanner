# eagle_packets_scanner.py


import os
import platform
import psutil
import scapy.all as scapy
import threading
import time
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError
from blessed import Terminal
from termcolor import colored
from tabulate import tabulate
from mac_vendor_lookup import MacLookup
import sys
import sqlite3


from eagle_packets_scanner.protocols import protocol_names

packet_data = []
temp_packet_data = []

sniffing = True

term = Terminal()

data_lock = threading.Lock()

mac_lookup = MacLookup()

source_ip_color = "white"
destination_ip_color = "white"
source_status_color = "green"
destination_status_color = "green"
protocol_color = "cyan"
reserved_color = "dark_grey"
suspicious_color = "red"
trustworthy_color = "green"
user_ip_color = "white"

db_filename = "packet_logs.db"

conn = sqlite3.connect(db_filename)
c = conn.cursor()
c.execute('''
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT,
    src_status TEXT,
    src_port TEXT,
    src_mac TEXT,
    src_vendor TEXT,
    dst_ip TEXT,
    dst_status TEXT,
    dst_port TEXT,
    dst_mac TEXT,
    dst_vendor TEXT,
    vlan TEXT,
    protocol TEXT,
    packet_summary TEXT,
    packet_length INTEGER,
    packet_time TEXT,
    program_name TEXT
)
''')
conn.commit()
conn.close()

def clear_screen():
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def cleanup():
    global sniffing
    sniffing = False
    print("\nStopping packet sniffing...")
    sys.exit(0)

import signal
signal.signal(signal.SIGINT, lambda sig, frame: cleanup())

filters = {
    "src_ip": None,  # Example filter
    "dst_ip": None,
    "protocol": None
}

def get_color(status):
    if status == "Trustworthy":
        return trustworthy_color
    elif status == "Suspicious":
        return suspicious_color
    elif status == "Private/Reserved":
        return reserved_color
    else:
        return "white"

def save_to_db(packet_data):
    conn = sqlite3.connect(db_filename)
    c = conn.cursor()
    for packet in packet_data:
        c.execute('''
        INSERT INTO packets (
            src_ip, src_status, src_port, src_mac, src_vendor,
            dst_ip, dst_status, dst_port, dst_mac, dst_vendor,
            vlan, protocol, packet_summary, packet_length, packet_time, program_name
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', packet)
    conn.commit()
    conn.close()

def start_packet_sniffing(interface):
    scapy.sniff(iface=interface, prn=lambda pkt: analyze_packets(pkt, filters, temp_packet_data, data_lock), store=False, stop_filter=lambda x: not sniffing)

def get_mac_vendor(mac_address):
    try:
        vendor = mac_lookup.lookup(mac_address)
        return vendor
    except Exception:
        return "Unknown Vendor"

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
        packet_summary = packet.summary() 

        src_mac = dst_mac = vlan = program_name = "N/A"  

        if packet.haslayer(scapy.Ether):
            src_mac = packet[scapy.Ether].src
            dst_mac = packet[scapy.Ether].dst

            src_vendor = get_mac_vendor(src_mac)
            dst_vendor = get_mac_vendor(dst_mac)

            if packet.haslayer(scapy.Dot1Q):
                vlan = packet[scapy.Dot1Q].vlan

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


def main():
    global temp_packet_data, last_displayed_packet_id

    try:
        temp_packet_data = []

        last_displayed_packet_id = float('-inf')

        interfaces = psutil.net_if_addrs()
        print("Available Network Interfaces:")
        for index, (interface_name, _) in enumerate(interfaces.items(), 1):
            print(f"{index}. {interface_name}")

        while True:
            try:
                interface_index = int(input("Enter the number of the interface you want to use: "))
                if 1 <= interface_index <= len(interfaces):
                    break
                else:
                    print("Invalid interface number. Please enter a valid number.")
            except ValueError:
                print("Invalid input. Please enter a number.")

        selected_interface = list(interfaces.keys())[interface_index - 1]
        print(f"Selected interface: {selected_interface}")

        sniffing_thread = threading.Thread(target=start_packet_sniffing, args=(selected_interface,))
        sniffing_thread.daemon = True
        sniffing_thread.start()

        while True:
            time.sleep(1)
            with data_lock:
                if temp_packet_data:
                    packet_data.extend(temp_packet_data)
                    save_to_db(temp_packet_data)
                    temp_packet_data = []

            if packet_data:
                combined_table = []
                for src, src_status, src_port, src_mac, src_vendor, dst, dst_status, dst_port, dst_mac, dst_vendor, vlan, protocol, packet_summary, packet_length, packet_time, program_name in packet_data:
                    combined_table.append([
                        colored(src, source_ip_color),
                        colored(src_status, get_color(src_status)),
                        colored(src_port, source_status_color),
                        colored(src_mac, source_status_color),
                        colored(src_vendor, source_status_color),
                        colored(dst, destination_ip_color),
                        colored(dst_status, get_color(dst_status)),
                        colored(dst_port, destination_status_color),
                        colored(dst_mac, destination_status_color),
                        colored(dst_vendor, destination_status_color),
                        colored(vlan, "yellow"),
                        colored(protocol, protocol_color),
                        colored(packet_summary, user_ip_color),
                        colored(packet_length, "magenta"),
                        colored(packet_time, "blue"),
                        colored(program_name, "white")
                    ])

                clear_screen()
                print(term.move_y(0) + term.clear + term.bold + term.white_on_black('Packet Sniffer Output') + term.normal)
                print(tabulate(combined_table, headers=["Source IP", "Source Status", "Port", "MAC", "Vendor", "Destination IP", "Destination Status", "Port", "MAC", "Vendor", "VLAN", "Protocol", "Packet Summary", "Packet Length", "Packet Time", "Program Name"]))

                last_displayed_packet_id = len(packet_data) - 1

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
