#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Packet Sniffer - Network Packet Capture and Analysis Tool
Author: Mathieu
Date: 11/04/2025
Description: Captures and analyzes network packets using raw sockets

⚠️  LEGAL WARNING ⚠️
This tool must only be used on networks where you have explicit authorization.
Intercepting communications without permission is illegal in most jurisdictions.
"""

import socket
import struct
import sys
import os
import platform
import textwrap
import argparse
import json
from datetime import datetime
from pathlib import Path
from colorama import init, Fore, Back, Style

# Initialize colorama for Windows compatibility
init(autoreset=True)


class PacketSniffer:
    """Main Packet Sniffer class"""
    
    def __init__(self, args=None):
        """Initialize the packet sniffer"""
        self.os_type = platform.system()
        self.running = False
        self.socket = None
        self.packet_count = 0
        self.args = args or argparse.Namespace()
        
        # Statistics
        self.stats = {
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'other': 0,
            'filtered': 0
        }
        
        # Port usage tracking
        self.port_usage = {}
        
        # Hostname cache for reverse DNS lookups
        self.hostname_cache = {}
        
        # Export features
        self.captured_packets = []  # Store packets for export
        self.export_json = getattr(args, 'export_json', None)
        self.export_txt = getattr(args, 'export_txt', None)
        self.output_dir = Path(getattr(args, 'output_dir', 'captures'))
        
        # Create output directory if export is enabled
        if self.export_json or self.export_txt:
            self.output_dir.mkdir(exist_ok=True)
        
        # Common port services (like Wireshark)
        self.port_services = {
            20: 'FTP-DATA',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            67: 'DHCP (Server)',
            68: 'DHCP (Client)',
            80: 'HTTP',
            110: 'POP3',
            123: 'NTP',
            143: 'IMAP',
            161: 'SNMP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt'
        }
        
        print(f"{Fore.CYAN}{Style.BRIGHT}{'=' * 70}")
        print("🔍 PACKET SNIFFER - Network Analysis Tool".center(70))
        print(f"{'=' * 70}{Style.RESET_ALL}")
        print()
    
    def get_protocol_color(self, protocol):
        """Return color for protocol type"""
        colors = {
            'TCP': Fore.GREEN,
            'UDP': Fore.BLUE,
            'ICMP': Fore.YELLOW,
            'OTHER': Fore.MAGENTA
        }
        return colors.get(protocol, Fore.WHITE)
    
    def print_header(self, text, color=Fore.CYAN):
        """Print a colored header"""
        print(f"\n{color}{Style.BRIGHT}{'=' * 70}")
        print(f"{text.center(70)}")
        print(f"{'=' * 70}{Style.RESET_ALL}")
    
    def print_separator(self, char='-', color=Fore.WHITE):
        """Print a separator line"""
        print(f"{color}{char * 70}{Style.RESET_ALL}")
    
    def print_field(self, label, value, color=Fore.WHITE):
        """Print a labeled field with color"""
        print(f"{Fore.CYAN}{label}:{Style.RESET_ALL} {color}{value}{Style.RESET_ALL}")
    
    def check_privileges(self):
        """Check if the program is running with necessary privileges"""
        if self.os_type == "Windows":
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if is_admin:
                    print(f"{Fore.GREEN}✅ Administrator privileges detected{Style.RESET_ALL}")
                    return True
                else:
                    print(f"{Fore.YELLOW}⚠️  No administrator privileges detected{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}   If you encounter errors, run as administrator{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}   Attempting to continue anyway...{Style.RESET_ALL}")
                    return True
            except Exception as e:
                print(f"{Fore.YELLOW}⚠️  Unable to check privileges: {e}{Style.RESET_ALL}")
                return True
                
        elif self.os_type == "Linux" or self.os_type == "Darwin":
            if os.geteuid() != 0:
                print(f"{Fore.RED}❌ ERROR: This program requires root privileges!{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}   Run with: sudo python3 main.py{Style.RESET_ALL}")
                return False
            print(f"{Fore.GREEN}✅ Root privileges detected{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.YELLOW}⚠️  Unrecognized operating system: {self.os_type}{Style.RESET_ALL}")
            return True
    
    def display_system_info(self):
        """Display system information"""
        print(f"\n{Fore.LIGHTCYAN_EX}📊 System Information:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}   - OS: {Fore.YELLOW}{self.os_type}{Fore.WHITE} ({platform.platform()}){Style.RESET_ALL}")
        print(f"{Fore.WHITE}   - Python: {Fore.YELLOW}{sys.version.split()[0]}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}   - Architecture: {Fore.YELLOW}{platform.machine()}{Style.RESET_ALL}")
        print()
    
    def show_legal_warning(self):
        """Display legal warning"""
        print(f"{Fore.YELLOW}{Style.BRIGHT}⚠️  {'=' * 66}")
        print("⚠️  LEGAL WARNING".center(68))
        print(f"⚠️  {'=' * 66}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⚠️  Using this tool to intercept communications without explicit")
        print("⚠️  authorization is ILLEGAL.")
        print(f"⚠️  Use only on your own networks or with proper permission.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{Style.BRIGHT}⚠️  {'=' * 66}{Style.RESET_ALL}")
        print()
        
        response = input(f"{Fore.CYAN}Do you confirm you have authorization ([y]/[n])? {Style.RESET_ALL}").lower()
        if response not in ['yes', 'y']:
            print(f"\n{Fore.RED}❌ Operation cancelled.{Style.RESET_ALL}")
            return False
        return True
    
    def create_socket(self):
        """Create a raw socket for packet capture"""
        try:
            if self.os_type == "Windows":
                # Windows: Create socket for IP protocol
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                # Get the first non-loopback IP address
                hostname = socket.gethostname()
                host_ip = socket.gethostbyname(hostname)
                
                # Bind to the local IP (required for Windows raw sockets)
                self.socket.bind((host_ip, 0))
                
                # Enable promiscuous mode
                self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                # Enable promiscuous mode using IOCTL - captures all traffic
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                print(f"{Fore.GREEN}✅ Raw socket created and bound to {host_ip}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}✅ Promiscuous mode enabled (captures all interfaces){Style.RESET_ALL}")
                
            elif self.os_type == "Linux":
                # Linux: Create socket for all protocols
                self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                print(f"{Fore.GREEN}✅ Raw socket created (AF_PACKET){Style.RESET_ALL}")
                
            elif self.os_type == "Darwin":
                # macOS: Similar to Linux but with different configuration
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                print(f"{Fore.GREEN}✅ Raw socket created (macOS){Style.RESET_ALL}")
            
            return True
            
        except PermissionError:
            print(f"{Fore.RED}❌ ERROR: Permission denied. Run as administrator/root!{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"{Fore.RED}❌ ERROR creating socket: {e}{Style.RESET_ALL}")
            return False
    
    def parse_ethernet_header(self, data):
        """Parse Ethernet header (14 bytes) - Only for Linux/macOS"""
        eth_header = struct.unpack('!6s6sH', data[:14])
        dest_mac = ':'.join(f'{b:02x}' for b in eth_header[0])
        src_mac = ':'.join(f'{b:02x}' for b in eth_header[1])
        eth_protocol = socket.ntohs(eth_header[2])
        
        return {
            'dest_mac': dest_mac,
            'src_mac': src_mac,
            'protocol': eth_protocol,
            'protocol_name': self.get_eth_protocol_name(eth_protocol)
        }
    
    def parse_ip_header(self, data):
        """Parse IP header (20 bytes minimum)"""
        # Unpack the first 20 bytes of IP header
        ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
        
        version_ihl = ip_header[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0xF) * 4  # Internet Header Length in bytes
        ttl = ip_header[5]
        protocol = ip_header[6]
        src_ip = socket.inet_ntoa(ip_header[8])
        dest_ip = socket.inet_ntoa(ip_header[9])
        
        return {
            'version': version,
            'header_length': ihl,
            'ttl': ttl,
            'protocol': protocol,
            'protocol_name': self.get_ip_protocol_name(protocol),
            'src_ip': src_ip,
            'dest_ip': dest_ip,
            'data': data[ihl:]  # Return remaining data after IP header
        }
    
    def parse_tcp_header(self, data):
        """Parse TCP header (20 bytes minimum)"""
        tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
        
        src_port = tcp_header[0]
        dest_port = tcp_header[1]
        sequence = tcp_header[2]
        acknowledgment = tcp_header[3]
        offset_reserved = tcp_header[4]
        tcp_header_length = (offset_reserved >> 4) * 4
        
        # TCP Flags
        flags = tcp_header[5]
        flag_urg = (flags & 32) >> 5
        flag_ack = (flags & 16) >> 4
        flag_psh = (flags & 8) >> 3
        flag_rst = (flags & 4) >> 2
        flag_syn = (flags & 2) >> 1
        flag_fin = flags & 1
        
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'sequence': sequence,
            'acknowledgment': acknowledgment,
            'flags': {
                'URG': flag_urg,
                'ACK': flag_ack,
                'PSH': flag_psh,
                'RST': flag_rst,
                'SYN': flag_syn,
                'FIN': flag_fin
            },
            'data': data[tcp_header_length:]
        }
    
    def parse_udp_header(self, data):
        """Parse UDP header (8 bytes)"""
        udp_header = struct.unpack('!HHHH', data[:8])
        
        src_port = udp_header[0]
        dest_port = udp_header[1]
        length = udp_header[2]
        
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'length': length,
            'data': data[8:]
        }
    
    def parse_icmp_header(self, data):
        """Parse ICMP header (8 bytes minimum)"""
        icmp_header = struct.unpack('!BBH', data[:4])
        
        icmp_type = icmp_header[0]
        code = icmp_header[1]
        checksum = icmp_header[2]
        
        return {
            'type': icmp_type,
            'type_name': self.get_icmp_type_name(icmp_type),
            'code': code,
            'checksum': checksum,
            'data': data[8:]
        }
    
    def get_eth_protocol_name(self, protocol):
        """Get Ethernet protocol name"""
        protocols = {
            0x0800: 'IPv4',
            0x0806: 'ARP',
            0x86DD: 'IPv6'
        }
        return protocols.get(protocol, f'Unknown (0x{protocol:04x})')
    
    def get_ip_protocol_name(self, protocol):
        """Get IP protocol name"""
        protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        return protocols.get(protocol, f'Other ({protocol})')
    
    def get_icmp_type_name(self, icmp_type):
        """Get ICMP type name"""
        types = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            8: 'Echo Request',
            11: 'Time Exceeded'
        }
        return types.get(icmp_type, f'Type {icmp_type}')
    
    def get_service_name(self, port):
        """Get service name for a port"""
        return self.port_services.get(port, 'Unknown')
    
    def get_hostname(self, ip_address):
        """Get hostname from IP address using reverse DNS lookup (cached)"""
        # Skip local/private IPs
        if ip_address.startswith(('10.', '172.', '192.168.', '127.')):
            return None
        
        # Check cache first
        if ip_address in self.hostname_cache:
            return self.hostname_cache[ip_address]
        
        try:
            # Perform reverse DNS lookup with timeout
            hostname = socket.gethostbyaddr(ip_address)[0]
            self.hostname_cache[ip_address] = hostname
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout):
            # If lookup fails, cache as None to avoid repeated lookups
            self.hostname_cache[ip_address] = None
            return None
    
    def track_port_usage(self, src_port, dest_port, protocol):
        """Track port usage statistics"""
        # Track both source and destination ports
        for port in [src_port, dest_port]:
            if port not in self.port_usage:
                self.port_usage[port] = {
                    'count': 0,
                    'protocol': protocol,
                    'service': self.get_service_name(port)
                }
            self.port_usage[port]['count'] += 1
    
    def format_hex_line(self, data, offset=0):
        """Format a line of data in hexadecimal view"""
        hex_part = ' '.join(f'{b:02x}' for b in data)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
        return f"{offset:04x}  {hex_part:<48}  {ascii_part}"
    
    def matches_filters(self, ip_info, transport_info=None):
        """Check if packet matches the configured filters"""
        # Protocol filter
        if hasattr(self.args, 'protocol') and self.args.protocol:
            protocol_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
            if ip_info['protocol'] != protocol_map.get(self.args.protocol.lower()):
                return False
        
        # Source IP filter
        if hasattr(self.args, 'src_ip') and self.args.src_ip:
            if ip_info['src_ip'] != self.args.src_ip:
                return False
        
        # Destination IP filter
        if hasattr(self.args, 'dest_ip') and self.args.dest_ip:
            if ip_info['dest_ip'] != self.args.dest_ip:
                return False
        
        # Port filter (requires transport_info)
        if transport_info and hasattr(self.args, 'port') and self.args.port:
            if 'src_port' in transport_info and 'dest_port' in transport_info:
                if self.args.port not in [transport_info['src_port'], transport_info['dest_port']]:
                    return False
        
        return True
    
    def create_packet_dict(self, packet_data, ip_info, transport_info, eth_info=None):
        """Create a dictionary representation of packet for export"""
        packet_dict = {
            'packet_number': self.packet_count,
            'timestamp': datetime.now().isoformat(),
            'size': len(packet_data) + (14 if self.os_type == 'Linux' and eth_info else 0),
            'ip': {
                'version': ip_info['version'],
                'header_length': ip_info['header_length'],
                'ttl': ip_info['ttl'],
                'protocol': ip_info['protocol_name'],
                'src_ip': ip_info['src_ip'],
                'dest_ip': ip_info['dest_ip']
            }
        }
        
        # Add Ethernet info for Linux
        if eth_info:
            packet_dict['ethernet'] = {
                'src_mac': eth_info['src_mac'],
                'dest_mac': eth_info['dest_mac'],
                'protocol': eth_info['protocol_name']
            }
        
        # Add hostname info if available
        dest_hostname = self.hostname_cache.get(ip_info['dest_ip'])
        src_hostname = self.hostname_cache.get(ip_info['src_ip'])
        if dest_hostname or src_hostname:
            packet_dict['hostnames'] = {}
            if dest_hostname:
                packet_dict['hostnames']['destination'] = dest_hostname
            if src_hostname:
                packet_dict['hostnames']['source'] = src_hostname
        
        # Add transport layer info
        if transport_info:
            if ip_info['protocol'] == 6:  # TCP
                packet_dict['tcp'] = {
                    'src_port': transport_info['src_port'],
                    'dest_port': transport_info['dest_port'],
                    'sequence': transport_info['sequence'],
                    'acknowledgment': transport_info['acknowledgment'],
                    'flags': {k: v for k, v in transport_info['flags'].items() if v},
                    'payload_length': len(transport_info['data'])
                }
            elif ip_info['protocol'] == 17:  # UDP
                packet_dict['udp'] = {
                    'src_port': transport_info['src_port'],
                    'dest_port': transport_info['dest_port'],
                    'length': transport_info['length'],
                    'payload_length': len(transport_info['data'])
                }
            elif ip_info['protocol'] == 1:  # ICMP
                packet_dict['icmp'] = {
                    'type': transport_info['type_name'],
                    'code': transport_info['code'],
                    'checksum': transport_info['checksum']
                }
        
        return packet_dict
    
    def display_parsed_packet(self, packet_data):
        """Parse and display packet information"""
        try:
            # For Linux: Parse Ethernet header first
            if self.os_type == "Linux":
                eth_info = self.parse_ethernet_header(packet_data)
                packet_data = packet_data[14:]  # Skip Ethernet header
            
            # Parse IP header
            ip_info = self.parse_ip_header(packet_data)
            
            # Parse transport layer based on protocol
            transport_info = None
            if ip_info['protocol'] == 6:  # TCP
                transport_info = self.parse_tcp_header(ip_info['data'])
                self.stats['tcp'] += 1
                # Track port usage
                self.track_port_usage(transport_info['src_port'], 
                                     transport_info['dest_port'], 'TCP')
            elif ip_info['protocol'] == 17:  # UDP
                transport_info = self.parse_udp_header(ip_info['data'])
                self.stats['udp'] += 1
                # Track port usage
                self.track_port_usage(transport_info['src_port'], 
                                     transport_info['dest_port'], 'UDP')
            elif ip_info['protocol'] == 1:  # ICMP
                transport_info = self.parse_icmp_header(ip_info['data'])
                self.stats['icmp'] += 1
            else:
                self.stats['other'] += 1
            
            # Apply filters
            if not self.matches_filters(ip_info, transport_info):
                self.stats['filtered'] += 1
                return  # Skip this packet
            
            # Store packet for export if enabled
            if self.export_json or self.export_txt:
                eth_info_dict = eth_info if self.os_type == "Linux" and 'eth_info' in locals() else None
                packet_dict = self.create_packet_dict(packet_data, ip_info, transport_info, eth_info_dict)
                self.captured_packets.append(packet_dict)
            
            # Display packet header
            protocol_color = self.get_protocol_color(ip_info['protocol_name'])
            print(f"\n{Style.BRIGHT}{protocol_color}{'═' * 70}")
            print(f"📦 Packet #{self.packet_count} | Size: {len(packet_data) + (14 if self.os_type == 'Linux' else 0)} bytes | {ip_info['protocol_name']}")
            print(f"{'═' * 70}{Style.RESET_ALL}")
            
            # Display Ethernet header for Linux
            if self.os_type == "Linux" and 'eth_info' in locals():
                print(f"\n{Fore.MAGENTA}🔷 Ethernet Header:{Style.RESET_ALL}")
                self.print_field("   Source MAC      ", eth_info['src_mac'], Fore.WHITE)
                self.print_field("   Destination MAC ", eth_info['dest_mac'], Fore.WHITE)
                self.print_field("   Protocol        ", eth_info['protocol_name'], Fore.CYAN)
            
            # Display IP header
            print(f"\n{Fore.MAGENTA}🔷 IP Header:{Style.RESET_ALL}")
            self.print_field("   Version         ", f"IPv{ip_info['version']}", Fore.WHITE)
            self.print_field("   Header Length   ", f"{ip_info['header_length']} bytes", Fore.WHITE)
            self.print_field("   TTL             ", str(ip_info['ttl']), Fore.WHITE)
            self.print_field("   Protocol        ", ip_info['protocol_name'], protocol_color)
            self.print_field("   Source IP       ", ip_info['src_ip'], Fore.YELLOW)
            self.print_field("   Destination IP  ", ip_info['dest_ip'], Fore.YELLOW)
            
            # Reverse DNS lookup for all packets (public IPs only)
            # Check destination IP first
            if not ip_info['dest_ip'].startswith(('10.', '172.', '192.168.', '127.')):
                dest_hostname = self.get_hostname(ip_info['dest_ip'])
                if dest_hostname:
                    self.print_field("   🌐 Dest Hostname ", dest_hostname, Fore.CYAN)
            
            # Check source IP (for incoming packets)
            if not ip_info['src_ip'].startswith(('10.', '172.', '192.168.', '127.')):
                src_hostname = self.get_hostname(ip_info['src_ip'])
                if src_hostname:
                    self.print_field("   🌐 Src Hostname  ", src_hostname, Fore.CYAN)
            
            # Display transport layer
            if ip_info['protocol'] == 6:  # TCP
                print(f"\n{Fore.GREEN}🔷 TCP Header:{Style.RESET_ALL}")
                self.print_field("   Source Port     ", str(transport_info['src_port']), Fore.LIGHTGREEN_EX)
                self.print_field("   Destination Port", str(transport_info['dest_port']), Fore.LIGHTGREEN_EX)
                
                self.print_field("   Sequence        ", str(transport_info['sequence']), Fore.WHITE)
                self.print_field("   Acknowledgment  ", str(transport_info['acknowledgment']), Fore.WHITE)
                
                flags_set = [flag for flag, value in transport_info['flags'].items() if value]
                flags_str = ', '.join(flags_set) if flags_set else 'None'
                self.print_field("   Flags           ", flags_str, Fore.LIGHTCYAN_EX)
                
                if len(transport_info['data']) > 0:
                    payload_preview = transport_info['data'][:50]
                    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload_preview)
                    print(f"\n{Fore.LIGHTBLACK_EX}🔷 Payload Preview: {printable}{Style.RESET_ALL}")
                    
            elif ip_info['protocol'] == 17:  # UDP
                print(f"\n{Fore.BLUE}🔷 UDP Header:{Style.RESET_ALL}")
                self.print_field("   Source Port     ", str(transport_info['src_port']), Fore.LIGHTBLUE_EX)
                self.print_field("   Destination Port", str(transport_info['dest_port']), Fore.LIGHTBLUE_EX)
                self.print_field("   Length          ", f"{transport_info['length']} bytes", Fore.WHITE)
                
                if len(transport_info['data']) > 0:
                    payload_preview = transport_info['data'][:50]
                    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload_preview)
                    print(f"\n{Fore.LIGHTBLACK_EX}🔷 Payload Preview: {printable}{Style.RESET_ALL}")
                    
            elif ip_info['protocol'] == 1:  # ICMP
                print(f"\n{Fore.YELLOW}🔷 ICMP Header:{Style.RESET_ALL}")
                self.print_field("   Type            ", transport_info['type_name'], Fore.LIGHTYELLOW_EX)
                self.print_field("   Code            ", str(transport_info['code']), Fore.WHITE)
                self.print_field("   Checksum        ", str(transport_info['checksum']), Fore.WHITE)
                
        except Exception as e:
            if hasattr(self.args, 'verbose') and self.args.verbose:
                print(f"\n{Fore.RED}⚠️  Error parsing packet: {e}{Style.RESET_ALL}")
                print(f"   Displaying raw data instead...")
                for i in range(0, min(64, len(packet_data)), 16):
                    line_data = packet_data[i:i+16]
                    print(self.format_hex_line(line_data, i))
        
        print()
    
    def capture_packets(self, count=10):
        """Capture and display packets"""
        if not self.socket:
            print("❌ ERROR: Socket not initialized!")
            return
        
        # Display active filters
        if hasattr(self.args, 'protocol') and self.args.protocol:
            print(f"{Fore.CYAN}🔍 Filter: Protocol = {self.args.protocol.upper()}{Style.RESET_ALL}")
        if hasattr(self.args, 'src_ip') and self.args.src_ip:
            print(f"{Fore.CYAN}🔍 Filter: Source IP = {self.args.src_ip}{Style.RESET_ALL}")
        if hasattr(self.args, 'dest_ip') and self.args.dest_ip:
            print(f"{Fore.CYAN}🔍 Filter: Destination IP = {self.args.dest_ip}{Style.RESET_ALL}")
        if hasattr(self.args, 'port') and self.args.port:
            print(f"{Fore.CYAN}🔍 Filter: Port = {self.args.port}{Style.RESET_ALL}")
        
        # Display export info
        if self.export_json or self.export_txt:
            print(f"\n{Fore.LIGHTCYAN_EX}📁 Export enabled:")
            if self.export_json:
                print(f"   - JSON format: {Fore.GREEN}✓{Style.RESET_ALL}")
            if self.export_txt:
                print(f"   - Text format: {Fore.GREEN}✓{Style.RESET_ALL}")
            print(f"   - Output directory: {Fore.YELLOW}{self.output_dir}{Style.RESET_ALL}")
        
        # Endless mode check
        endless_mode = (count == 0)
        if endless_mode:
            print(f"\n🎯 Starting packet capture in ENDLESS MODE...")
            print("Press Ctrl+C to stop\n")
        else:
            print(f"\n🎯 Starting packet capture (max {count} packets)...")
            print("Press Ctrl+C to stop\n")
        
        self.running = True
        displayed_count = 0
        
        try:
            while self.running:
                # Check if we should stop (only in non-endless mode)
                if not endless_mode and displayed_count >= count:
                    break
                
                # Receive packet
                packet_data, addr = self.socket.recvfrom(65535)
                self.packet_count += 1
                
                # Parse and display packet information
                prev_filtered = self.stats['filtered']
                self.display_parsed_packet(packet_data)
                
                # Only increment displayed count if packet wasn't filtered
                if self.stats['filtered'] == prev_filtered:
                    displayed_count += 1
                
        except KeyboardInterrupt:
            print("\n⚠️  Capture interrupted by user")
        finally:
            self.cleanup()
    
    def display_port_analysis(self):
        """Display port usage analysis table (Wireshark-style)"""
        if not self.port_usage:
            return
        
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'═' * 70}")
        print(f"🔌 PORT USAGE ANALYSIS")
        print(f"{'═' * 70}{Style.RESET_ALL}")
        
        # Sort ports by usage count (descending)
        sorted_ports = sorted(self.port_usage.items(), 
                             key=lambda x: x[1]['count'], 
                             reverse=True)
        
        # Display table header
        print(f"{Fore.YELLOW}{Style.BRIGHT}{'Port':<8} {'Protocol':<10} {'Service':<20} {'Count':<10}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{'-' * 70}{Style.RESET_ALL}")
        
        # Display port statistics
        for port, data in sorted_ports[:15]:  # Show top 15 ports
            service = data['service']
            protocol = data['protocol']
            count = data['count']
            
            # Color code by protocol
            protocol_color = Fore.GREEN if protocol == 'TCP' else Fore.BLUE
            
            # Highlight well-known ports
            if service != 'Unknown':
                print(f"{Fore.LIGHTWHITE_EX}{port:<8} {protocol_color}{protocol:<10}{Style.RESET_ALL} "
                      f"{Fore.CYAN}{service:<20}{Style.RESET_ALL} {Fore.LIGHTYELLOW_EX}{count:<10}{Style.RESET_ALL}")
            else:
                print(f"{Fore.LIGHTWHITE_EX}{port:<8} {protocol_color}{protocol:<10}{Style.RESET_ALL} "
                      f"{Fore.LIGHTBLACK_EX}{'Unknown':<20}{Style.RESET_ALL} {Fore.LIGHTYELLOW_EX}{count:<10}{Style.RESET_ALL}")
        
        # Show if there are more ports
        if len(sorted_ports) > 15:
            remaining = len(sorted_ports) - 15
            print(f"{Fore.WHITE}{'-' * 70}{Style.RESET_ALL}")
            print(f"{Fore.LIGHTBLACK_EX}... and {remaining} more port(s){Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")
        
        # Display HTTPS hostnames discovered
        if self.hostname_cache:
            https_hosts = {ip: hostname for ip, hostname in self.hostname_cache.items() 
                          if hostname is not None}
            if https_hosts:
                print(f"\n{Fore.CYAN}{Style.BRIGHT}{'═' * 70}")
                print(f"🌐 DISCOVERED HOSTNAMES (Reverse DNS)")
                print(f"{'═' * 70}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}{Style.BRIGHT}{'IP Address':<20} {'Hostname':<50}{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{'-' * 70}{Style.RESET_ALL}")
                for ip, hostname in sorted(https_hosts.items()):
                    print(f"{Fore.LIGHTYELLOW_EX}{ip:<20}{Style.RESET_ALL} {Fore.LIGHTCYAN_EX}{hostname:<50}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")
    
    def export_to_json(self):
        """Export captured packets to JSON file"""
        if not self.captured_packets:
            print(f"\n{Fore.YELLOW}⚠️  No packets to export{Style.RESET_ALL}")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"capture_{timestamp}.json"
        
        export_data = {
            'metadata': {
                'capture_date': datetime.now().isoformat(),
                'total_packets': len(self.captured_packets),
                'os_type': self.os_type,
                'filters': {
                    'protocol': getattr(self.args, 'protocol', None),
                    'src_ip': getattr(self.args, 'src_ip', None),
                    'dest_ip': getattr(self.args, 'dest_ip', None),
                    'port': getattr(self.args, 'port', None)
                },
                'statistics': self.stats
            },
            'packets': self.captured_packets
        }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            print(f"\n{Fore.GREEN}✅ JSON export successful: {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}❌ Error exporting to JSON: {e}{Style.RESET_ALL}")
    
    def export_to_txt(self):
        """Export captured packets to text file"""
        if not self.captured_packets:
            print(f"\n{Fore.YELLOW}⚠️  No packets to export{Style.RESET_ALL}")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"capture_{timestamp}.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=" * 70 + "\n")
                f.write("PACKET SNIFFER - CAPTURE REPORT\n")
                f.write("=" * 70 + "\n\n")
                
                # Write metadata
                f.write(f"Capture Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Operating System: {self.os_type}\n")
                f.write(f"Total Packets Captured: {len(self.captured_packets)}\n")
                
                # Write filters
                filters_active = False
                if hasattr(self.args, 'protocol') and self.args.protocol:
                    f.write(f"Protocol Filter: {self.args.protocol.upper()}\n")
                    filters_active = True
                if hasattr(self.args, 'src_ip') and self.args.src_ip:
                    f.write(f"Source IP Filter: {self.args.src_ip}\n")
                    filters_active = True
                if hasattr(self.args, 'dest_ip') and self.args.dest_ip:
                    f.write(f"Destination IP Filter: {self.args.dest_ip}\n")
                    filters_active = True
                if hasattr(self.args, 'port') and self.args.port:
                    f.write(f"Port Filter: {self.args.port}\n")
                    filters_active = True
                if not filters_active:
                    f.write("Filters: None\n")
                
                f.write("\n" + "=" * 70 + "\n")
                f.write("STATISTICS\n")
                f.write("=" * 70 + "\n")
                f.write(f"TCP packets: {self.stats['tcp']}\n")
                f.write(f"UDP packets: {self.stats['udp']}\n")
                f.write(f"ICMP packets: {self.stats['icmp']}\n")
                f.write(f"Other packets: {self.stats['other']}\n")
                f.write(f"Filtered out: {self.stats['filtered']}\n")
                
                f.write("\n" + "=" * 70 + "\n")
                f.write("PACKET DETAILS\n")
                f.write("=" * 70 + "\n\n")
                
                # Write packet details
                for packet in self.captured_packets:
                    f.write(f"\nPacket #{packet['packet_number']}\n")
                    f.write(f"Timestamp: {packet['timestamp']}\n")
                    f.write(f"Size: {packet['size']} bytes\n")
                    
                    # IP info
                    f.write(f"\nIP Header:\n")
                    f.write(f"  Protocol: {packet['ip']['protocol']}\n")
                    f.write(f"  Source IP: {packet['ip']['src_ip']}\n")
                    f.write(f"  Destination IP: {packet['ip']['dest_ip']}\n")
                    f.write(f"  TTL: {packet['ip']['ttl']}\n")
                    
                    # Hostnames
                    if 'hostnames' in packet:
                        f.write(f"\nHostnames:\n")
                        if 'source' in packet['hostnames']:
                            f.write(f"  Source: {packet['hostnames']['source']}\n")
                        if 'destination' in packet['hostnames']:
                            f.write(f"  Destination: {packet['hostnames']['destination']}\n")
                    
                    # Transport layer
                    if 'tcp' in packet:
                        f.write(f"\nTCP Header:\n")
                        f.write(f"  Source Port: {packet['tcp']['src_port']}\n")
                        f.write(f"  Destination Port: {packet['tcp']['dest_port']}\n")
                        f.write(f"  Sequence: {packet['tcp']['sequence']}\n")
                        f.write(f"  Acknowledgment: {packet['tcp']['acknowledgment']}\n")
                        if packet['tcp']['flags']:
                            f.write(f"  Flags: {', '.join(packet['tcp']['flags'].keys())}\n")
                    elif 'udp' in packet:
                        f.write(f"\nUDP Header:\n")
                        f.write(f"  Source Port: {packet['udp']['src_port']}\n")
                        f.write(f"  Destination Port: {packet['udp']['dest_port']}\n")
                        f.write(f"  Length: {packet['udp']['length']} bytes\n")
                    elif 'icmp' in packet:
                        f.write(f"\nICMP Header:\n")
                        f.write(f"  Type: {packet['icmp']['type']}\n")
                        f.write(f"  Code: {packet['icmp']['code']}\n")
                    
                    f.write(f"\n{'-' * 70}\n")
            
            print(f"\n{Fore.GREEN}✅ Text export successful: {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}❌ Error exporting to text: {e}{Style.RESET_ALL}")
    
    def cleanup(self):
        """Clean up resources"""
        if self.socket:
            try:
                if self.os_type == "Windows":
                    # Disable promiscuous mode
                    self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                self.socket.close()
                
                # Display statistics
                print(f"\n{Fore.CYAN}{Style.BRIGHT}{'═' * 70}")
                print(f"📊 CAPTURE STATISTICS")
                print(f"{'═' * 70}{Style.RESET_ALL}")
                
                total_displayed = self.packet_count - self.stats['filtered']
                
                print(f"{Fore.WHITE}   Total packets processed : {Style.BRIGHT}{self.packet_count}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}   TCP packets            : {Style.BRIGHT}{self.stats['tcp']}{Style.RESET_ALL}")
                print(f"{Fore.BLUE}   UDP packets            : {Style.BRIGHT}{self.stats['udp']}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}   ICMP packets           : {Style.BRIGHT}{self.stats['icmp']}{Style.RESET_ALL}")
                print(f"{Fore.MAGENTA}   Other packets          : {Style.BRIGHT}{self.stats['other']}{Style.RESET_ALL}")
                print(f"{Fore.LIGHTBLACK_EX}   Filtered out           : {Style.BRIGHT}{self.stats['filtered']}{Style.RESET_ALL}")
                print(f"{Fore.LIGHTCYAN_EX}   Displayed              : {Style.BRIGHT}{total_displayed}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")
                
                # Display port analysis
                self.display_port_analysis()
                
                # Export captured packets if requested
                if self.export_json:
                    self.export_to_json()
                
                if self.export_txt:
                    self.export_to_txt()
                
            except Exception as e:
                print(f"{Fore.RED}⚠️  Error during cleanup: {e}{Style.RESET_ALL}")
    
    def run(self):
        """Start the packet sniffer"""
        self.display_system_info()
        
        if not self.check_privileges():
            return False
        
        if not self.show_legal_warning():
            return False
        
        print(f"\n{Fore.GREEN}✅ Configuration complete!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🔧 Creating raw socket...{Style.RESET_ALL}\n")
        
        if not self.create_socket():
            return False
        
        # Get packet count from args or use default
        count = getattr(self.args, 'count', 10)
        self.capture_packets(count=count)
        return True


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='Packet Sniffer - Network packet capture and analysis tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
        Examples:
          python main.py                           # Capture 10 packets (default)
          python main.py -c 50                     # Capture 50 packets
          python main.py -c 0                      # Endless mode (Ctrl+C to stop)
          python main.py -p tcp                    # Capture only TCP packets
          python main.py -p udp --port 53          # Capture UDP packets on port 53
          python main.py --src-ip 192.168.1.100    # Capture from specific source IP
          python main.py --dest-ip 8.8.8.8         # Capture to specific destination IP
          python main.py -p tcp --port 80 -c 20    # Capture 20 TCP packets on port 80
          python main.py -v                        # Verbose mode (show parsing errors)
          python main.py -c 0 -p tcp --port 443    # Endless HTTPS monitoring
          python main.py -c 100 --export-json      # Capture 100 packets and export to JSON
          python main.py -c 50 --export-txt        # Capture 50 packets and export to text
          python main.py --export-json --export-txt --output-dir logs  # Export to both formats in logs/ directory
        
        Note: Requires administrator/root privileges
        ''')
    )
    
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=10,
        metavar='N',
        help='Number of packets to capture (default: 10, use 0 for endless mode)'
    )
    
    parser.add_argument(
        '-p', '--protocol',
        type=str,
        choices=['tcp', 'udp', 'icmp', 'TCP', 'UDP', 'ICMP'],
        metavar='PROTO',
        help='Filter by protocol (tcp, udp, icmp)'
    )
    
    parser.add_argument(
        '--src-ip',
        type=str,
        metavar='IP',
        help='Filter by source IP address'
    )
    
    parser.add_argument(
        '--dest-ip',
        type=str,
        metavar='IP',
        help='Filter by destination IP address'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        metavar='PORT',
        help='Filter by port number (source or destination)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose mode (show parsing errors)'
    )
    
    parser.add_argument(
        '--export-json',
        action='store_true',
        help='Export captured packets to JSON file'
    )
    
    parser.add_argument(
        '--export-txt',
        action='store_true',
        help='Export captured packets to text file'
    )
    
    parser.add_argument(
        '--output-dir',
        type=str,
        default='captures',
        metavar='DIR',
        help='Output directory for exported files (default: captures/)'
    )
    
    return parser.parse_args()
        

def main():
    """Program entry point"""
    try:
        args = parse_arguments()
        sniffer = PacketSniffer(args)
        sniffer.run()
        
    except KeyboardInterrupt:
        print("\n\n⚠️  User interruption (Ctrl+C)")
        print("Stopping program...")
    except Exception as e:
        print(f"\n❌ FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Keep window open
        print("\n" + "=" * 70)
        input("Press Enter to exit...")


if __name__ == "__main__":
    main()
