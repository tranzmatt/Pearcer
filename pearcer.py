#!/usr/bin/env python3
"""
Pearcer - Professional Packet Analyzer & Security Suite
A clean, professional, and efficient packet analysis tool.

Copyright (c) 2025 Jackson Pearce <Telegram: @H4CKRD>
Licensed under GNU General Public License v3.0
"""

import argparse
import binascii
import hashlib
import html
import json
import math
import os
import re
import socket
import struct
import sys
import threading
import time
import urllib.parse
from collections import defaultdict, deque
from datetime import datetime
from queue import Queue, Empty

# ============================================================================
# PLATFORM DETECTION
# ============================================================================

IS_WINDOWS = sys.platform.startswith('win')
IS_LINUX = sys.platform.startswith('linux')

# ============================================================================
# OPTIONAL DEPENDENCIES
# ============================================================================

SCAPY_AVAILABLE = False
try:
    from scapy.all import (
        sniff, Ether, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR,
        ARP, BootP, BootPS, Raw, conf, get_if_list, get_if_addr
    )
    SCAPY_AVAILABLE = True
    # Export Raw for use in packet processing
    ScapyRaw = Raw
except ImportError:
    ScapyRaw = None

PSUTIL_AVAILABLE = False
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    pass

# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG_FILE = "pearcer_config.json"

DEFAULT_CONFIG = {
    "interface": "eth0" if IS_LINUX else "Wi-Fi",
    "promiscuous": True,
    "bpf_filter": "",
    "capture_mode": "live",
    "headless": False,
    "remote_agent_port": 9999,
    
    # Performance settings - tuned for smooth operation
    "packet_queue_size": 5000,
    "max_captured_packets": 50000,
    "max_displayed_packets": 1000,
    "gui_update_interval_ms": 500,
    "batch_size": 25,
    
    # Filtering
    "filter_mode": "all",
    "display_filter": "",
    
    # Security scanning
    "auto_vuln_scan": False,
    "attack_threshold": 50,
    
    # Blacklist/Whitelist
    "blacklist_ips": [],
    "whitelist_ips": [],
    
    # Protocol preferences
    "protocols": {
        "tcp": True,
        "udp": True,
        "icmp": True,
        "http": True,
        "dns": True,
        "tls": True,
        "arp": True,
    },
    
    # UI preferences
    "theme": "dark",
    "font_size": 10,
    "show_hex": True,
    "auto_scroll": True,
    
    # Coloring rules (Wireshark-inspired)
    "colors": {
        "tcp": {"fg": "#000000", "bg": "#E6E6FA"},
        "udp": {"fg": "#000000", "bg": "#dae8fc"},
        "http": {"fg": "#000000", "bg": "#d5e8d4"},
        "dns": {"fg": "#000000", "bg": "#fff2cc"},
        "icmp": {"fg": "#000000", "bg": "#e1d5e7"},
        "arp": {"fg": "#000000", "bg": "#fafad2"},
        "tls": {"fg": "#000000", "bg": "#f5f5f5"},
        "suspicious": {"fg": "#FFFFFF", "bg": "#FF8C00"},
        "attack": {"fg": "#FFFFFF", "bg": "#DC143C"},
        "error": {"fg": "#FFFFFF", "bg": "#8B0000"},
    },
    
    # Logging
    "log_file": "pearcer.log",
    "pcap_output": "capture.pcap",
}


def load_config():
    """Load configuration from file or use defaults."""
    config = DEFAULT_CONFIG.copy()
    
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                file_config = json.load(f)
                config.update(file_config)
        except (json.JSONDecodeError, IOError) as e:
            print(f"[WARN] Could not load config file: {e}")
    
    return config


def save_config(config):
    """Save configuration to file."""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2, sort_keys=True)
    except IOError as e:
        print(f"[ERROR] Could not save config: {e}")


# ============================================================================
# NETWORK INTERFACE DISCOVERY
# ============================================================================

def get_interfaces():
    """Get available network interfaces with caching."""
    interfaces = []
    
    if SCAPY_AVAILABLE:
        try:
            interfaces = get_if_list()
        except Exception:
            pass
    
    if not interfaces and PSUTIL_AVAILABLE:
        try:
            interfaces = list(psutil.net_if_stats().keys())
        except Exception:
            pass
    
    if not interfaces:
        # Fallback to common interface names
        if IS_WINDOWS:
            interfaces = ['Wi-Fi', 'Ethernet', 'Local Area Connection']
        else:
            interfaces = ['eth0', 'wlan0', 'lo', 'any']
    
    return sorted(set(interfaces))


def get_interface_info(iface_name):
    """Get detailed information about a network interface."""
    info = {
        'name': iface_name,
        'ip': None,
        'mac': None,
        'status': 'unknown',
        'speed': None,
    }
    
    if PSUTIL_AVAILABLE:
        try:
            stats = psutil.net_if_stats()
            if iface_name in stats:
                iface_stats = stats[iface_name]
                info['status'] = 'up' if iface_stats.isup else 'down'
                info['speed'] = iface_stats.speed
        except Exception:
            pass
        
        try:
            addrs = psutil.net_if_addrs()
            if iface_name in addrs:
                for addr in addrs[iface_name]:
                    if addr.family == socket.AF_INET:
                        info['ip'] = addr.address
                    elif addr.family == 17:  # AF_LINK on some systems
                        info['mac'] = addr.address
        except Exception:
            pass
    
    if SCAPY_AVAILABLE and not info['ip']:
        try:
            info['ip'] = get_if_addr(iface_name)
        except Exception:
            pass
    
    return info


# ============================================================================
# PACKET DATA STRUCTURES
# ============================================================================

class PacketInfo:
    """Structured packet information for display and analysis."""
    
    __slots__ = [
        'id', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
        'protocol', 'length', 'flags', 'info', 'raw_data', 'tags',
        'ttl', 'entropy', 'direction'
    ]
    
    def __init__(self, pkt_id, timestamp, src_ip, dst_ip, src_port, dst_port,
                 protocol, length, info, raw_data=None, tags=None, ttl=None):
        self.id = pkt_id
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.length = length
        self.flags = ''
        self.info = info
        self.raw_data = raw_data
        self.tags = tags or []
        self.ttl = ttl
        self.entropy = 0.0
        self.direction = 'outbound'
    
    def to_dict(self):
        """Convert to dictionary for serialization."""
        return {
            'id': self.id,
            'time': datetime.fromtimestamp(self.timestamp).strftime('%H:%M:%S.%f')[:-3],
            'src': f"{self.src_ip}:{self.src_port}" if self.src_port else self.src_ip,
            'dst': f"{self.dst_ip}:{self.dst_port}" if self.dst_port else self.dst_ip,
            'proto': self.protocol,
            'len': self.length,
            'info': self.info,
            'tags': self.tags,
        }
    
    def summary(self):
        """Return a human-readable summary."""
        time_str = datetime.fromtimestamp(self.timestamp).strftime('%H:%M:%S.%f')[:-3]
        src = f"{self.src_ip}:{self.src_port}" if self.src_port else self.src_ip
        dst = f"{self.dst_ip}:{self.dst_port}" if self.dst_port else self.dst_ip
        return f"{time_str} | {self.protocol:6s} | {src:24s} -> {dst:24s} | {self.info}"


# ============================================================================
# PROTOCOL DETECTION & ANALYSIS
# ============================================================================

TLS_HANDSHAKE = b'\x16\x03'
HTTP_METHODS = [b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS', b'PATCH']
DNS_PORT = 53
HTTP_PORTS = [80, 8080, 8000, 8888]
HTTPS_PORTS = [443, 8443]


def calculate_entropy(data):
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    
    byte_counts = defaultdict(int)
    for byte in data:
        byte_counts[byte] += 1
    
    entropy = 0.0
    data_len = len(data)
    for count in byte_counts.values():
        if count > 0:
            p = count / data_len
            entropy -= p * math.log2(p)
    
    return entropy


def detect_protocol(payload, ip_proto, src_port, dst_port):
    """Detect application-layer protocol from packet data."""
    protocol = 'DATA'
    
    # Check by port first
    if dst_port == DNS_PORT or src_port == DNS_PORT:
        protocol = 'DNS'
    elif dst_port in HTTPS_PORTS or src_port in HTTPS_PORTS:
        protocol = 'TLS'
    elif dst_port in HTTP_PORTS or src_port in HTTP_PORTS:
        protocol = 'HTTP'
    
    # Check payload signatures
    if payload:
        if payload[:2] == TLS_HANDSHAKE:
            protocol = 'TLS'
        elif any(payload.startswith(method) for method in HTTP_METHODS):
            protocol = 'HTTP'
        elif b'HTTP/' in payload:
            protocol = 'HTTP'
        elif ip_proto == 1:  # ICMP
            protocol = 'ICMP'
        elif ip_proto == 17 and len(payload) >= 12:  # UDP with potential DNS
            protocol = 'DNS'
    
    return protocol


def extract_http_info(payload):
    """Extract relevant information from HTTP traffic."""
    info_parts = []
    
    try:
        text = payload.decode('utf-8', errors='ignore')
        
        # Extract method and path
        for method in HTTP_METHODS:
            if text.startswith(method.decode()):
                lines = text.split('\r\n')
                if lines:
                    parts = lines[0].split(' ')
                    if len(parts) >= 2:
                        info_parts.append(f"{method.decode()} {parts[1]}")
                break
        
        # Extract Host header
        host_match = re.search(r'Host:\s*([^\r\n]+)', text, re.IGNORECASE)
        if host_match:
            info_parts.append(f"Host: {host_match.group(1)}")
        
        # Extract User-Agent
        ua_match = re.search(r'User-Agent:\s*([^\r\n]+)', text, re.IGNORECASE)
        if ua_match:
            ua = ua_match.group(1)[:50]
            info_parts.append(f"UA: {ua}")
        
        # Extract Content-Type
        ct_match = re.search(r'Content-Type:\s*([^\r\n]+)', text, re.IGNORECASE)
        if ct_match:
            info_parts.append(f"Type: {ct_match.group(1)}")
    
    except Exception:
        pass
    
    return '; '.join(info_parts) if info_parts else 'HTTP Traffic'


def extract_dns_info(payload):
    """Extract relevant information from DNS traffic."""
    if len(payload) < 12:
        return 'DNS Query'
    
    try:
        # Simple DNS parsing (header only)
        flags = struct.unpack('>H', payload[2:4])[0]
        qr = (flags >> 15) & 1
        opcode = (flags >> 11) & 0xF
        
        if qr == 0:
            return 'DNS Query'
        else:
            return 'DNS Response'
    except Exception:
        return 'DNS Traffic'


def analyze_tcp_flags(flags):
    """Analyze TCP flags and return description."""
    flag_descriptions = []
    
    if flags & 0x02:
        flag_descriptions.append('SYN')
    if flags & 0x10:
        flag_descriptions.append('ACK')
    if flags & 0x01:
        flag_descriptions.append('FIN')
    if flags & 0x04:
        flag_descriptions.append('RST')
    if flags & 0x08:
        flag_descriptions.append('PSH')
    if flags & 0x20:
        flag_descriptions.append('URG')
    
    return ','.join(flag_descriptions) if flag_descriptions else ''


# ============================================================================
# THREAT DETECTION
# ============================================================================

class ThreatDetector:
    """Detect potential security threats in network traffic."""
    
    def __init__(self, threshold=50):
        self.threshold = threshold
        self.connection_counts = defaultdict(int)
        self.syn_counts = defaultdict(int)
        self.port_scan_detection = defaultdict(set)
        self.suspicious_patterns = [
            b'/etc/passwd',
            b'/etc/shadow',
            b'cmd.exe',
            b'powershell',
            b'wget ',
            b'curl ',
            b'nc -e',
            b'/bin/sh',
            b'SELECT.*FROM',
            b'UNION SELECT',
            b'<script>',
            b'javascript:',
        ]
        self.last_alert_time = {}
        self.alert_cooldown = 5.0  # seconds
    
    def analyze_packet(self, pkt_info, payload):
        """Analyze a packet for potential threats."""
        threats = []
        now = time.time()
        
        src_ip = pkt_info.src_ip
        dst_ip = pkt_info.dst_ip
        key = f"{src_ip}->{dst_ip}"
        
        # Track connection rate
        self.connection_counts[key] += 1
        
        # Detect SYN flood
        if 'SYN' in pkt_info.flags and 'ACK' not in pkt_info.flags:
            self.syn_counts[src_ip] += 1
            if self.syn_counts[src_ip] > self.threshold:
                if now - self.last_alert_time.get(key, 0) > self.alert_cooldown:
                    threats.append('Possible SYN Flood Attack')
                    self.last_alert_time[key] = now
        
        # Detect port scanning
        if pkt_info.dst_port:
            self.port_scan_detection[src_ip].add(pkt_info.dst_port)
            if len(self.port_scan_detection[src_ip]) > 20:
                if now - self.last_alert_time.get(src_ip, 0) > self.alert_cooldown:
                    threats.append(f'Port Scan Detected ({len(self.port_scan_detection[src_ip])} ports)')
                    self.last_alert_time[src_ip] = now
        
        # Check for suspicious payloads
        if payload:
            for pattern in self.suspicious_patterns:
                if pattern in payload.lower() if isinstance(pattern, bytes) else pattern.encode() in payload:
                    threats.append(f'Suspicious Pattern: {pattern.decode() if isinstance(pattern, bytes) else pattern}')
                    break
        
        # High entropy detection (possible encryption/malware)
        if payload and len(payload) > 100:
            entropy = calculate_entropy(payload)
            if entropy > 7.5:
                pkt_info.entropy = entropy
                # Only alert on very high entropy in suspicious contexts
                if pkt_info.dst_port not in HTTPS_PORTS and pkt_info.protocol != 'TLS':
                    threats.append(f'High Entropy Data (encryption?): {entropy:.2f}')
        
        return threats
    
    def reset(self):
        """Reset all detection counters."""
        self.connection_counts.clear()
        self.syn_counts.clear()
        self.port_scan_detection.clear()
        self.last_alert_time.clear()


# ============================================================================
# PACKET CAPTURE ENGINE
# ============================================================================

class CaptureEngine:
    """High-performance packet capture engine using Scapy."""
    
    def __init__(self, interface, bpf_filter="", promiscuous=True):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.promiscuous = promiscuous
        self.running = False
        self.packet_count = 0
        self.error_count = 0
        self.start_time = None
        self._lock = threading.Lock()
    
    def start(self, callback, count=0):
        """Start capturing packets."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for packet capture")
        
        self.running = True
        self.start_time = time.time()
        self.packet_count = 0
        self.error_count = 0
        
        def packet_callback(pkt):
            if not self.running:
                return
            try:
                self.packet_count += 1
                callback(pkt)
            except Exception as e:
                self.error_count += 1
                print(f"[CAPTURE ERROR] {e}")
        
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=packet_callback,
                store=False,
                count=count if count > 0 else 0,
                promisc=self.promiscuous,
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            print("[ERROR] Permission denied. Run with sudo/root privileges.")
            self.running = False
            raise
        except Exception as e:
            print(f"[ERROR] Capture failed: {e}")
            self.running = False
            raise
    
    def stop(self):
        """Stop capturing packets."""
        self.running = False
    
    def get_stats(self):
        """Get capture statistics."""
        elapsed = time.time() - self.start_time if self.start_time else 0
        return {
            'packets': self.packet_count,
            'errors': self.error_count,
            'elapsed': elapsed,
            'pps': self.packet_count / elapsed if elapsed > 0 else 0,
        }


# ============================================================================
# PACKET PROCESSOR
# ============================================================================

class PacketProcessor:
    """Process captured packets into structured format."""
    
    def __init__(self, max_packets=50000):
        self.max_packets = max_packets
        self.packets = deque(maxlen=max_packets)
        self.packet_id = 0
        self.lock = threading.Lock()
        self.threat_detector = ThreatDetector()
        self.stats = {
            'total': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'http': 0,
            'dns': 0,
            'tls': 0,
            'other': 0,
            'threats': 0,
        }
        self.hosts = set()
        self.connections = set()
    
    def process_scapy_packet(self, pkt):
        """Process a Scapy packet into PacketInfo."""
        with self.lock:
            self.packet_id += 1
            pkt_id = self.packet_id
            self.stats['total'] += 1
        
        timestamp = float(pkt.time)
        src_ip = dst_ip = None
        src_port = dst_port = None
        ip_proto = 0
        tcp_flags = ''
        payload = b''
        length = len(pkt)
        ttl = None
        
        # Extract IP layer
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            ip_proto = pkt[IP].proto
            ttl = pkt[IP].ttl
            self.hosts.add(src_ip)
            self.hosts.add(dst_ip)
            self.connections.add((src_ip, dst_ip))
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            ip_proto = pkt[IPv6].nh
            self.hosts.add(src_ip)
            self.hosts.add(dst_ip)
            self.connections.add((src_ip, dst_ip))
        
        # Extract transport layer
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            tcp_flags = analyze_tcp_flags(pkt[TCP].flags)
            self.stats['tcp'] += 1
            
            if ScapyRaw and ScapyRaw in pkt:
                payload = bytes(pkt[ScapyRaw].load)
            
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            self.stats['udp'] += 1
            
            if ScapyRaw and ScapyRaw in pkt:
                payload = bytes(pkt[ScapyRaw].load)
            
        elif ICMP in pkt:
            self.stats['icmp'] += 1
            if ScapyRaw and ScapyRaw in pkt:
                payload = bytes(pkt[ScapyRaw].load)
        
        # Detect protocol
        protocol = detect_protocol(payload, ip_proto, src_port, dst_port)
        
        # Update protocol stats
        proto_lower = protocol.lower()
        if proto_lower in self.stats:
            self.stats[proto_lower] += 1
        else:
            self.stats['other'] += 1
        
        # Extract protocol-specific info
        info = ''
        if protocol == 'HTTP':
            info = extract_http_info(payload)
        elif protocol == 'DNS':
            info = extract_dns_info(payload)
        elif protocol == 'TLS':
            info = 'TLS Handshake' if payload and payload[:2] == TLS_HANDSHAKE else 'TLS Data'
        elif tcp_flags:
            info = f'TCP [{tcp_flags}]'
        elif ICMP in pkt:
            info = f'ICMP Type={pkt[ICMP].type} Code={pkt[ICMP].code}'
        else:
            info = f'{protocol} Traffic'
        
        # Create packet info object
        pkt_info = PacketInfo(
            pkt_id=pkt_id,
            timestamp=timestamp,
            src_ip=src_ip or '0.0.0.0',
            dst_ip=dst_ip or '0.0.0.0',
            src_port=src_port or 0,
            dst_port=dst_port or 0,
            protocol=protocol,
            length=length,
            info=info,
            raw_data=payload[:1024] if payload else None,
            ttl=ttl,
        )
        pkt_info.flags = tcp_flags
        
        # Threat detection
        threats = self.threat_detector.analyze_packet(pkt_info, payload)
        if threats:
            pkt_info.tags.extend(threats)
            self.stats['threats'] += 1
        
        # Store packet
        with self.lock:
            self.packets.append(pkt_info)
        
        return pkt_info
    
    def get_recent_packets(self, count=100):
        """Get the most recent packets."""
        with self.lock:
            return list(self.packets)[-count:]
    
    def get_stats(self):
        """Get processing statistics."""
        with self.lock:
            return self.stats.copy()
    
    def get_hosts(self):
        """Get discovered hosts."""
        with self.lock:
            return self.hosts.copy()
    
    def get_connections(self):
        """Get discovered connections."""
        with self.lock:
            return self.connections.copy()
    
    def clear(self):
        """Clear all stored packets and stats."""
        with self.lock:
            self.packets.clear()
            self.packet_id = 0
            self.stats = {k: 0 for k in self.stats}
            self.hosts.clear()
            self.connections.clear()
            self.threat_detector.reset()


# ============================================================================
# HEADLESS CLI MODE
# ============================================================================

class HeadlessCLI:
    """Command-line interface for headless operation."""
    
    def __init__(self, config):
        self.config = config
        self.processor = PacketProcessor(
            max_packets=config.get('max_captured_packets', 50000)
        )
        self.engine = None
        self.running = False
    
    def start_capture(self, interface=None, bpf_filter="", count=0):
        """Start packet capture in headless mode."""
        iface = interface or self.config.get('interface', 'eth0')
        filter_str = bpf_filter or self.config.get('bpf_filter', '')
        
        print(f"[*] Starting capture on interface: {iface}")
        print(f"[*] BPF Filter: {filter_str or '(none)'}")
        print(f"[*] Press Ctrl+C to stop\n")
        
        self.engine = CaptureEngine(iface, filter_str)
        self.running = True
        
        def on_packet(pkt):
            pkt_info = self.processor.process_scapy_packet(pkt)
            
            # Print packet summary
            print(pkt_info.summary())
            
            # Print threats
            if pkt_info.tags:
                for threat in pkt_info.tags:
                    print(f"    [!] THREAT: {threat}")
        
        try:
            self.engine.start(on_packet, count=count)
        except KeyboardInterrupt:
            print("\n[*] Stopping capture...")
            self.stop_capture()
        except Exception as e:
            print(f"[ERROR] Capture failed: {e}")
            return False
        
        return True
    
    def stop_capture(self):
        """Stop the capture."""
        self.running = False
        if self.engine:
            self.engine.stop()
        
        # Print final statistics
        stats = self.processor.get_stats()
        capture_stats = self.engine.get_stats() if self.engine else {}
        
        print("\n" + "="*60)
        print("CAPTURE STATISTICS")
        print("="*60)
        print(f"Total Packets:  {stats['total']}")
        print(f"TCP:            {stats['tcp']}")
        print(f"UDP:            {stats['udp']}")
        print(f"ICMP:           {stats['icmp']}")
        print(f"HTTP:           {stats['http']}")
        print(f"DNS:            {stats['dns']}")
        print(f"TLS:            {stats['tls']}")
        print(f"Threats:        {stats['threats']}")
        print(f"Capture Rate:   {capture_stats.get('pps', 0):.2f} pps")
        print(f"Duration:       {capture_stats.get('elapsed', 0):.2f}s")
        print("="*60)
        
        # Print discovered hosts
        hosts = self.processor.get_hosts()
        if hosts:
            print(f"\nDiscovered Hosts ({len(hosts)}):")
            for host in sorted(hosts):
                print(f"  - {host}")
    
    def run_offline_analysis(self, pcap_file):
        """Analyze an existing PCAP file."""
        if not SCAPY_AVAILABLE:
            print("[ERROR] Scapy is required for offline analysis")
            return
        
        if not os.path.exists(pcap_file):
            print(f"[ERROR] File not found: {pcap_file}")
            return
        
        print(f"[*] Analyzing PCAP file: {pcap_file}\n")
        
        try:
            from scapy.all import rdpcap
            packets = rdpcap(pcap_file)
            
            for pkt in packets:
                pkt_info = self.processor.process_scapy_packet(pkt)
                print(pkt_info.summary())
                
                if pkt_info.tags:
                    for threat in pkt_info.tags:
                        print(f"    [!] THREAT: {threat}")
            
            self.stop_capture()
            
        except Exception as e:
            print(f"[ERROR] Failed to analyze PCAP: {e}")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point for Pearcer."""
    parser = argparse.ArgumentParser(
        description="Pearcer - Professional Packet Analyzer & Security Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --headless                    Run in headless CLI mode
  %(prog)s -i eth0 --headless            Capture on eth0 in headless mode
  %(prog)s -f "tcp port 80" --headless   Capture HTTP traffic only
  %(prog)s --analyze capture.pcap        Analyze existing PCAP file
  %(prog)s --interfaces                  List available interfaces
        """
    )
    
    parser.add_argument(
        '-i', '--interface',
        help='Network interface to capture on'
    )
    parser.add_argument(
        '-f', '--filter',
        help='BPF capture filter (e.g., "tcp port 80")'
    )
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=0,
        help='Number of packets to capture (0 = unlimited)'
    )
    parser.add_argument(
        '--headless',
        action='store_true',
        help='Run in headless CLI mode (no GUI)'
    )
    parser.add_argument(
        '--analyze',
        metavar='PCAP',
        help='Analyze existing PCAP file'
    )
    parser.add_argument(
        '--interfaces',
        action='store_true',
        help='List available network interfaces'
    )
    parser.add_argument(
        '--config',
        metavar='FILE',
        help='Use custom configuration file'
    )
    parser.add_argument(
        '--save-config',
        action='store_true',
        help='Save current configuration and exit'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 2.0.0'
    )
    
    args = parser.parse_args()
    
    # Load configuration
    if args.config:
        global CONFIG_FILE
        CONFIG_FILE = args.config
    
    config = load_config()
    
    # Handle --interfaces
    if args.interfaces:
        print("Available Network Interfaces:")
        print("-" * 50)
        for iface in get_interfaces():
            info = get_interface_info(iface)
            status = "UP" if info['status'] == 'up' else "DOWN"
            ip = info['ip'] or 'No IP'
            print(f"  {iface:20s} [{status}]  IP: {ip}")
        return 0
    
    # Handle --save-config
    if args.save_config:
        save_config(config)
        print(f"Configuration saved to: {CONFIG_FILE}")
        return 0
    
    # Handle --analyze
    if args.analyze:
        cli = HeadlessCLI(config)
        cli.run_offline_analysis(args.analyze)
        return 0
    
    # Default to headless mode (GUI not available in this environment)
    cli = HeadlessCLI(config)
    
    # Override config with CLI arguments
    interface = args.interface or config.get('interface')
    bpf_filter = args.filter or config.get('bpf_filter', '')
    count = args.count or 0
    
    # Start capture
    success = cli.start_capture(
        interface=interface,
        bpf_filter=bpf_filter,
        count=count
    )
    
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
