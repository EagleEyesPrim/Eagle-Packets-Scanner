# protocols.py
# Copyright 2024 Eagle Eyes Prim
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.




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
