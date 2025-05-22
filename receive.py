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
            # This script assumes a 20-byte IP header for locating the counter_data.
            # For robustness, ip_header_actual_len should be from (ip.version_ihl & 0xF) * 4
            assumed_ip_header_len = 20 
            ip_data_segment = raw_data[14 : 14 + assumed_ip_header_len] # Use assumed length for consistency here

            if len(ip_data_segment) < assumed_ip_header_len:
                print("  Not enough data for assumed IP header.")
                continue
            
            ip = parse_ip_header(ip_data_segment)
            
            print('\nIPv4 Packet:')
            actual_ip_header_len = (ip.version_ihl & 0xF) * 4 # Calculate actual for completeness of info
            print(f'Version: {ip.version_ihl >> 4}, Header Length: {actual_ip_header_len} bytes')
            print(f'TTL: {ip.ttl}, Protocol: {ip.protocol}') # Will be 6 (TCP) due to current P4
            print(f'Source: {format_ip(ip.src_addr)}, Destination: {format_ip(ip.dest_addr)}')
            
            # The counter header comes after Ethernet (14) + assumed IPv4 (20) = 34 bytes
            counter_header_start_offset = 14 + assumed_ip_header_len
            counter_data = raw_data[counter_header_start_offset : counter_header_start_offset + 2]

            if len(counter_data) == 2:
                counter = parse_counter_header(counter_data)
                print('\nCounter Header:')
                print(f'Counter value: {counter.value}')

                # --- ADDITION TO SHOW THE MESSAGE STARTS HERE ---
                # Based on current P4: Eth | IP(proto=6, totalLen=original) | CounterHeader | TCP | Message
                if ip.protocol == 6: # Check if the original protocol was TCP
                    # TCP Header starts after Eth (14) + assumed_IP_Hdr (20) + Counter_Hdr (2) = 36
                    tcp_header_start_offset = counter_header_start_offset + 2
                    
                    # Assume a standard TCP header length of 20 bytes (no options)
                    # A robust solution would parse the TCP Data Offset field.
                    assumed_tcp_header_length = 20
                    
                    message_start_offset = tcp_header_start_offset + assumed_tcp_header_length

                    # The original IP total_len field (ip.total_len) from the IP header
                    # tells us the length of the original IP datagram (IP Header + original TCP segment).
                    # P4 (in this version) did not modify ip.total_len.
                    # So, length of original TCP segment = ip.total_len - actual_ip_header_len
                    if ip.total_len > actual_ip_header_len : # Ensure total_len is greater than header_len
                        original_tcp_segment_length = ip.total_len - actual_ip_header_len
                        
                        if original_tcp_segment_length > assumed_tcp_header_length:
                            message_payload_length = original_tcp_segment_length - assumed_tcp_header_length
                            
                            # Ensure we have enough bytes in the raw_data packet
                            if len(raw_data) >= message_start_offset + message_payload_length:
                                message_bytes = raw_data[message_start_offset : message_start_offset + message_payload_length]
                                print('\nMessage:')
                                try:
                                    print(f'  {message_bytes.decode("utf-8", errors="replace")}')
                                except Exception as e_decode:
                                    print(f'  Could not decode message: {e_decode}')
                                print(f'  Raw Hex: {message_bytes.hex()}')
                            else:
                                print("\nMessage: Not enough data in received frame for calculated message length.")
                        elif original_tcp_segment_length == assumed_tcp_header_length:
                            print('\nMessage: (empty TCP payload, based on IP total_len)')
                        else:
                            print(f"\nMessage: Calculated original TCP segment length ({original_tcp_segment_length}) is not greater than assumed TCP header length ({assumed_tcp_header_length}).")
                    else:
                        print(f"\nMessage: IP total length ({ip.total_len}) not greater than IP header length ({actual_ip_header_len}).")
                else:
                    print(f"\nNot a TCP packet (Original Protocol: {ip.protocol}), cannot extract TCP message.")
                # --- ADDITION TO SHOW THE MESSAGE ENDS HERE ---
            else:
                print('\nNo counter header found or incomplete')
        else:
            print('\nNot an IPv4 packet')

# Keep the rest of your functions (parse_ethernet_header, parse_ip_header, etc.) as they are.
# Ensure these helper functions are defined in your script:
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