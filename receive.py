#!/usr/bin/env python3

import socket
import struct
import textwrap
from collections import namedtuple

# Constants
TYPE_IPV4 = 0x0800

# Header formats
eth_header = struct.Struct('!6s6sH')
ip_header = struct.Struct('!BBHHHBBH4s4s')
counter_header = struct.Struct('!H')

# Named tuples for parsed headers
EthHeader = namedtuple('EthHeader', ['dest', 'src', 'type'])
IpHeader = namedtuple('IpHeader', ['version_ihl', 'diffserv', 'total_len', 'identification',
                                  'flags_frag_offset', 'ttl', 'protocol', 'checksum',
                                  'src_addr', 'dest_addr'])
CounterHeader = namedtuple('CounterHeader', ['value'])

def main():
    # Create raw socket to listen on all interfaces
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))  # ETH_P_ALL
    
    print("Waiting for packets...")
    
    while True:
        raw_data, addr = conn.recvfrom(65535)
        
        # Parse Ethernet header
        eth = parse_ethernet_header(raw_data[:14])
        print('\nEthernet Frame:')
        print(f'Destination: {format_mac(eth.dest)}, Source: {format_mac(eth.src)}, Type: {hex(eth.type)}')
        
        # If IPv4 packet
        if eth.type == TYPE_IPV4:
            # Parse IP header (first 20 bytes after Ethernet)
            ip = parse_ip_header(raw_data[14:34])
            
            print('\nIPv4 Packet:')
            print(f'Version: {ip.version_ihl >> 4}, Header Length: {(ip.version_ihl & 0xF) * 4} bytes')
            print(f'TTL: {ip.ttl}, Protocol: {ip.protocol}')
            print(f'Source: {format_ip(ip.src_addr)}, Destination: {format_ip(ip.dest_addr)}')
            
            # The counter header comes after Ethernet (14) + IPv4 (20) = 34 bytes
            counter_data = raw_data[34:36]
            if len(counter_data) == 2:
                counter = parse_counter_header(counter_data)
                print('\nCounter Header:')
                print(f'Counter value: {counter.value}')
            else:
                print('\nNo counter header found or incomplete')
        else:
            print('\nNot an IPv4 packet')

def parse_ethernet_header(data):
    dest, src, eth_type = eth_header.unpack(data)
    return EthHeader(dest, src, eth_type)

def parse_ip_header(data):
    version_ihl, diffserv, total_len, identification, flags_frag, ttl, proto, checksum, src, dest = ip_header.unpack(data)
    return IpHeader(version_ihl, diffserv, total_len, identification, flags_frag, ttl, proto, checksum, src, dest)

def parse_counter_header(data):
    value, = counter_header.unpack(data)
    return CounterHeader(value)

def format_mac(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def format_ip(bytes_addr):
    return '.'.join(map(str, bytes_addr))

if __name__ == '__main__':
    main()