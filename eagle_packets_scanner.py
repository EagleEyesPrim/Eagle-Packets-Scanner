import os
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
import protocols
import sys
import sqlite3

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
protocol_names = protocols.protocol_names

# Colors
source_ip_color = "white"
destination_ip_color = "white"
source_status_color = "green"
destination_status_color = "green"
protocol_color = "cyan"
reserved_color = "dark_grey"
suspicious_color = "red"
trustworthy_color = "green"
user_ip_color = "white"

# Log file name
log_filename = "packet_logs.txt"
db_filename = "DataResult.db"

# Create database connection
def create_db_connection():
    conn = sqlite3.connect(db_filename)
    return conn

# Create tables in the database
def create_tables(conn):
    with conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT,
                source_status TEXT,
                source_port TEXT,
                source_mac TEXT,
                destination_ip TEXT,
                destination_status TEXT,
                destination_port TEXT,
                destination_mac TEXT,
                vlan TEXT,
                protocol TEXT,
                packet_summary TEXT,
                packet_length INTEGER,
                packet_time TEXT,
                program_name TEXT
            )
        ''')

# Save packet data to the database
def save_to_db(packet):
    conn = create_db_connection()
    try:
        with conn:
            conn.execute('''
                INSERT INTO packets (
                    source_ip, source_status, source_port, source_mac,
                    destination_ip, destination_status, destination_port, destination_mac,
                    vlan, protocol, packet_summary, packet_length, packet_time, program_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', packet)
    finally:
        conn.close()

# Define the function to save the latest packet data to a log file
def save_latest_to_log(packet_data):
    if packet_data:
        with open(log_filename, 'w') as file:  # Use 'w' to overwrite the file
            table_str = tabulate(packet_data, headers=["Source IP", "Source Status", "Port", "MAC", "Destination IP", "Destination Status", "Port", "MAC", "VLAN", "Protocol", "Packet Summary", "Packet Length", "Packet Time", "Program Name"])
            file.write(table_str + "\n")

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

# Function to clear the screen based on the operating system
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Function to handle cleanup on exit
def cleanup():
    global sniffing
    sniffing = False
    with data_lock:
        save_latest_to_log(packet_data)
    print("\nStopping packet sniffing...")
    sys.exit(0)

# Set up signal handler for clean exit
import signal
signal.signal(signal.SIGINT, lambda sig, frame: cleanup())

# Function to get color based on status
def get_color(status):
    if status == "Trustworthy":
        return trustworthy_color
    elif status == "Suspicious":
        return suspicious_color
    elif status == "Private/Reserved":
        return reserved_color
    else:
        return "white"

# Function to analyze packets
def analyze_packets(packet):
    if packet.haslayer(scapy.IP):
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

        packet_entry = (ip_src, src_status, src_port, src_mac, ip_dst, dst_status, dst_port, dst_mac, vlan, protocol_name, packet_summary, packet_length, packet_time, program_name)
        
        with data_lock:
            temp_packet_data.append(packet_entry)
            save_to_db(packet_entry)

# Main function
def main():
    global temp_packet_data, last_displayed_packet_id

    try:
        # Initialize temp_packet_data to an empty list
        temp_packet_data = []

        # Set last_displayed_packet_id to negative infinity initially
        last_displayed_packet_id = float('-inf')

        # Create database connection and tables
        conn = create_db_connection()
        create_tables(conn)
        conn.close()

        # Get available network interfaces
        interfaces = psutil.net_if_addrs()
        print("Available Network Interfaces:")
        for index, (interface_name, _) in enumerate(interfaces.items(), 1):
            print(f"{index}. {interface_name}")

        # Select the interface used by the user on the device
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
                    temp_packet_data = []

            if packet_data:
                combined_table = []
                for src, src_status, src_port, src_mac, dst, dst_status, dst_port, dst_mac, vlan, protocol, packet_summary, packet_length, packet_time, program_name in packet_data:
                    combined_table.append([
                        colored(src, source_ip_color),
                        colored(src_status, get_color(src_status)),
                        colored(src_port, source_status_color),  # Add source port
                        colored(src_mac, source_status_color),  # Add source MAC
                        colored(dst, destination_ip_color),
                        colored(dst_status, get_color(dst_status)),
                        colored(dst_port, destination_status_color),  # Add destination port
                        colored(dst_mac, destination_status_color),  # Add destination MAC
                        colored(vlan, destination_status_color),  # Add VLAN
                        colored(protocol, protocol_color),
                        colored(packet_summary, protocol_color),  # Add package summary
                        packet_length,
                        packet_time,
                        program_name  # Add program name
                    ])

                with term.location():
                    clear_screen()  # Clear the screen before printing the new table
                    print(term.orange_on_black(term.center("EPS - Eagle Packets Scanner")))
                    print(term.move_y(1) + "Network Traffic and Protocol Analysis Table:")
                    table_str = tabulate(combined_table,
                    headers=["Source IP", "Source Status", "Port", "MAC", "Destination IP", "Destination Status", "Port", "MAC", "VLAN", "Protocol", "Packet Summary", "Packet Length", "Packet Time", "Program Name"])
                    print(term.move_y(2) + term.move_x(-5) + table_str)
                    # Save the latest packet data to the log file
                    save_latest_to_log(packet_data)

    except KeyboardInterrupt:
        cleanup()

if __name__ == "__main__":
    main()
