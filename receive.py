#!/usr/bin/env python3

import socket # sending and receiving network data
import struct # for parsing structs
from collections import namedtuple # tuple subclasses for named fields (better reading)

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
    # listen on all interfaces
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))  # ETH_P_ALL
    
    print("Waiting for packets...")
    
    while True:
        raw_data, addr = conn.recvfrom(65535)
        
        eth = parse_ethernet_header(raw_data[:14])
        
        # if its an ipv4 packet then
        if eth.type == TYPE_IPV4:
            print('\nEthernet Frame:')
            print(f'Destination: {format_mac(eth.dest)}, Source: {format_mac(eth.src)}, Type: TYPE_IPV4') 
            
            assumed_ip_header_len = 20 
            ip_data_segment = raw_data[14 : 14 + assumed_ip_header_len]
            
            if len(ip_data_segment) < assumed_ip_header_len:
                continue
            
            ip = parse_ip_header(ip_data_segment) 
            
            print('\nIPv4 Packet:')
            actual_ip_header_len = (ip.version_ihl & 0xF) * 4 
            print(f'Version: {ip.version_ihl >> 4}, Header Length: {actual_ip_header_len} bytes')
            
            protocol_display = "TCP" if ip.protocol == 6 else str(ip.protocol)
            print(f'TTL: {ip.ttl}, Protocol: {protocol_display}') 
            
            print(f'Source: {format_ip(ip.src_addr)}, Destination: {format_ip(ip.dest_addr)}')
            
            counter_header_start_offset = 14 + assumed_ip_header_len 
            counter_data = raw_data[counter_header_start_offset : counter_header_start_offset + 2]

            if len(counter_data) == 2:
                counter = parse_counter_header(counter_data)
                print('\nCounter Header:')
                print(f'Counter value: {counter.value}')

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