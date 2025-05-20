#!/usr/bin/env python3
import sys
from scapy.all import *
from scapy.fields import XIntField
from scapy.packet import Packet

# Custom protocol number (choose an unused one, e.g., 99, 253, 254)
CUSTOM_PROTO = 99
TYPE_IPV4 = 0x0800

# Define CounterHeader
class CounterHeader(Packet):
    name = "CounterHeader"
    fields_desc = [
        XIntField("cont_value", 0)  # cont_value with default 0
    ]

# Bind layers:
# - Ethernet -> IP (standard, type=0x0800)
# - IP -> CounterHeader (when IP.proto == CUSTOM_PROTO)
bind_layers(Ether, IP, type=TYPE_IPV4)  # Standard IPv4
bind_layers(IP, CounterHeader, proto=CUSTOM_PROTO)  # Critical: Tell Scapy to parse CounterHeader after IP if proto=99

def handle_pkt(pkt):
    if CounterHeader in pkt:
        print("\n=== Received Packet ===")
        pkt.show2()  # Show full packet structure
        print(f"Counter Value: {pkt[CounterHeader].cont_value}")
        sys.stdout.flush()

def main():
    iface = next((i for i in get_if_list() if 'eth0' in i or 's0' in i), None)
    if not iface:
        print("Cannot find eth0 or s0 interface")
        return
    
    print(f"Sniffing on {iface}")
    sniff(iface=iface, prn=handle_pkt)

if __name__ == '__main__':
    main()