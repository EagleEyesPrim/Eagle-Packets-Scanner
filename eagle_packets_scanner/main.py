#Get From Eviro
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

#Get From Home
from packet_functions import analyze_packets
import protocols
import sys

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

# Initialize MacLookup instance
mac_lookup = MacLookup()

# Define filters (these can be set by user input)
filters = {
    "src_ip": None,  # Example filter
    "dst_ip": None,
    "protocol": None
}

# Function to clear the screen based on the operating system
def clear_screen():
    os.system('cls' if platform.system() == 'Windows' else 'clear')

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

# Function to save the latest packet data to a log file
def save_latest_to_log(packet_data):
    if packet_data:
        with open(log_filename, 'w') as file:  # Use 'w' to overwrite the file
            table_str = tabulate(packet_data, headers=["Source IP", "Source Status", "Port", "MAC", "Vendor", "Destination IP", "Destination Status", "Port", "MAC", "Vendor", "VLAN", "Protocol", "Packet Summary", "Packet Length", "Packet Time", "Program Name"])
            file.write(table_str + "\n")

# Function to start packet sniffing
def start_packet_sniffing(interface):
    scapy.sniff(iface=interface, prn=lambda pkt: analyze_packets(pkt, filters, temp_packet_data, data_lock), store=False, stop_filter=lambda x: not sniffing)

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

def main():
    global temp_packet_data, last_displayed_packet_id
    
    print("Eagle Packets Scanner is running")
    
    try:
        # Initialize temp_packet_data to an empty list
        temp_packet_data = []

        # Set last_displayed_packet_id to negative infinity initially
        last_displayed_packet_id = float('-inf')

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
                for src, src_status, src_port, src_mac, src_vendor, dst, dst_status, dst_port, dst_mac, dst_vendor, vlan, protocol, packet_summary, packet_length, packet_time, program_name in packet_data:
                    combined_table.append([
                        colored(src, source_ip_color),
                        colored(src_status, get_color(src_status)),
                        colored(src_port, source_status_color),  # Add source port
                        colored(src_mac, source_status_color),  # Add source MAC
                        colored(src_vendor, source_status_color),  # Add source Vendor
                        colored(dst, destination_ip_color),
                        colored(dst_status, get_color(dst_status)),
                        colored(dst_port, destination_status_color),  # Add destination port
                        colored(dst_mac, destination_status_color),  # Add destination MAC
                        colored(dst_vendor, destination_status_color),  # Add destination Vendor
                        colored(vlan, "yellow"),
                        colored(protocol, protocol_color),
                        colored(packet_summary, user_ip_color),
                        colored(packet_length, "magenta"),
                        colored(packet_time, "white"),
                        colored(program_name, "white")
                    ])

                clear_screen()
                print(term.move_y(0) + term.clear + term.bold + term.white_on_black('Packet Sniffer Output') + term.normal)
                print(tabulate(combined_table, headers=["Source IP", "Source Status", "Port", "MAC", "Vendor", "Destination IP", "Destination Status", "Port", "MAC", "Vendor", "VLAN", "Protocol", "Packet Summary", "Packet Length", "Packet Time", "Program Name"]))

                last_displayed_packet_id = len(packet_data) - 1

            save_latest_to_log(packet_data)

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
