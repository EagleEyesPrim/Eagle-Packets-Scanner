import scapy.all as scapy
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

def analyze_packets(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst}")
        check_ip_reputation(ip_src)
        check_ip_reputation(ip_dst)

def check_ip_reputation(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        if 'entities' in res:
            print(f"IP: {ip} is trustworthy.")
        else:
            print(f"IP: {ip} is suspicious.")
    except IPDefinedError:
        print(f"IP: {ip} is a private or reserved IP.")
    except Exception as e:
        print(f"Could not determine the reputation of IP: {ip}. Error: {e}")

def start_packet_sniffing():
    print("Starting packet sniffing...")
    scapy.sniff(prn=analyze_packets, store=False)

def eagle_scanner():
    start_packet_sniffing()

if __name__ == "__eagle_scanner__":
    eagle_scanner()
