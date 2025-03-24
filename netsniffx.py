import socket
import struct
import textwrap
from datetime import datetime

# ANSI Colors
GREEN = "\033[92m"
BLUE = "\033[94m"
RESET = "\033[0m"

def sniff_packets(interface, filter_protocol=None):
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        if filter_protocol and eth_proto != filter_protocol:
            continue
        print(f"{BLUE}Ethernet Frame:{RESET}")
        print(f"Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")
        if eth_proto == 8:  # IPv4
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print(f"{GREEN}IPv4 Packet:{RESET}")
            print(f"Version: {version}, Header Length: {header_length}, TTL: {ttl}")
            print(f"Protocol: {proto}, Source: {src}, Target: {target}")
            if proto == 6:  # TCP
                src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print(f"{GREEN}TCP Segment:{RESET}")
                print(f"Source Port: {src_port}, Destination Port: {dest_port}")
                print(f"Sequence: {sequence}, Acknowledgment: {ack}")
                print(f"Flags: URG={flag_urg}, ACK={flag_ack}, PSH={flag_psh}, RST={flag_rst}, SYN={flag_syn}, FIN={flag_fin}")
                if src_port == 80 or dest_port == 80:  # HTTP
                    print(f"{GREEN}HTTP Data:{RESET}")
                    print(data.decode(errors="ignore"))

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    return ':'.join(f'{byte:02x}' for byte in bytes_addr)

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def tcp_segment(data):
    (src_port, dest_port, sequence, ack, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

if __name__ == "__main__":
    print(f"{GREEN}Starting NetSniffX...{RESET}")
    sniff_packets("eth0", filter_protocol=8)  # Change "eth0" to your interface