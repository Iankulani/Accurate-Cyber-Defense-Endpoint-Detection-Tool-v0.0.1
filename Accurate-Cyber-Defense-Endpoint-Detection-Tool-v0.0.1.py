"""
ACCURATE CYBER DEFENSE ENDPOINT DETECTION TOOL 
Author: Ian Carter Kulani
Version: 0.0.1
Integrated Features: Network Monitoring, Intrusion Detection, Traffic Generation, 
                     Threat Analysis, Telegram Integration, Advanced Scanning,
                     Real-time Charts, Dark/Light Themes, Database Logging
"""

import sys
import os
import time
import json
import logging
import configparser
from typing import Dict, List, Set, Tuple, Optional, Any
from pathlib import Path
from datetime import datetime, timedelta
import threading
import queue
import argparse
import signal
import hashlib
import base64
import zipfile
import tempfile
import math

# Core imports
import socket
import subprocess
import requests
import random
import platform
import psutil
import getpass
import sqlite3
import ipaddress
import re
import shutil

from collections import defaultdict, Counter

# GUI imports
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, scrolledtext, font
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
    print("Warning: GUI features require tkinter")

# Chart imports
try:
    import matplotlib.pyplot as plt
    import matplotlib.animation as animation
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
    from matplotlib.figure import Figure
    from matplotlib import style
    style.use('ggplot')
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("Warning: Chart features require matplotlib")

# Security imports
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("Warning: nmap features require python-nmap")

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Packet features require scapy")

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False

# Constants
VERSION = "3.0.0"
AUTHOR = "Cyber Security War Tool Team"
DEFAULT_CONFIG_FILE = "config.ini"
DATABASE_FILE = "network_threats.db"
REPORT_DIR = "reports"
LOG_DIR = "logs"
HISTORY_FILE = "command_history.txt"
MAX_HISTORY = 1000
TELEGRAM_API_URL = "https://api.telegram.org/bot"

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# Themes for GUI
THEMES = {
    "dark": {
        "bg": "#121212",
        "fg": "#00ff00",
        "text_bg": "#222222",
        "text_fg": "#ffffff",
        "button_bg": "#333333",
        "button_fg": "#00ff00",
        "highlight": "#006600",
        "chart_bg": "#1a1a1a",
        "chart_grid": "#333333"
    },
    "light": {
        "bg": "#f0f0f0",
        "fg": "#000000",
        "text_bg": "#ffffff",
        "text_fg": "#000000",
        "button_bg": "#e0e0e0",
        "button_fg": "#000000",
        "highlight": "#a0a0a0",
        "chart_bg": "#ffffff",
        "chart_grid": "#dddddd"
    },
    "cyber": {
        "bg": "#0a0a1a",
        "fg": "#00ffff",
        "text_bg": "#151530",
        "text_fg": "#ffffff",
        "button_bg": "#1a1a3a",
        "button_fg": "#00ffff",
        "highlight": "#00aaff",
        "chart_bg": "#0f0f25",
        "chart_grid": "#252545"
    }
}

class TracerouteTool:
    """Enhanced interactive traceroute tool"""
    
    @staticmethod
    def is_ipv4_or_ipv6(address: str) -> bool:
        """Check if input is valid IPv4 or IPv6 address"""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_hostname(name: str) -> bool:
        """Check if input is valid hostname"""
        if name.endswith('.'):
            name = name[:-1]
        HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")
        return bool(HOSTNAME_RE.match(name))

    @staticmethod
    def choose_traceroute_cmd(target: str) -> List[str]:
        """Return appropriate traceroute command for the system"""
        system = platform.system()

        if system == 'Windows':
            return ['tracert', '-d', target]

        # On Unix-like systems
        if shutil.which('traceroute'):
            return ['traceroute', '-n', '-q', '1', '-w', '2', target]
        if shutil.which('tracepath'):
            return ['tracepath', target]
        if shutil.which('ping'):
            return ['ping', '-c', '4', target]

        raise EnvironmentError('No traceroute utilities found')

    @staticmethod
    def stream_subprocess(cmd: List[str]) -> Tuple[int, str]:
        """Run subprocess and capture output"""
        output_lines = []
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

            if proc.stdout:
                for line in proc.stdout:
                    cleaned_line = line.rstrip()
                    output_lines.append(cleaned_line)
                    print(cleaned_line)

            proc.wait()
            return proc.returncode, '\n'.join(output_lines)
        except KeyboardInterrupt:
            print('\n[+] User cancelled traceroute...')
            try:
                proc.terminate()
            except Exception:
                pass
            return -1, '\n'.join(output_lines)
        except Exception as e:
            error_msg = f'[!] Error: {e}'
            print(error_msg)
            output_lines.append(error_msg)
            return -2, '\n'.join(output_lines)

    def interactive_traceroute(self, target: str = None) -> str:
        """Run interactive traceroute with validation"""
        if not target:
            target = self.prompt_target()
            if not target:
                return "Traceroute cancelled."

        if not (self.is_ipv4_or_ipv6(target) or self.is_valid_hostname(target)):
            return f"❌ Invalid IP address or hostname: {target}"

        try:
            cmd = self.choose_traceroute_cmd(target)
        except EnvironmentError as e:
            return f"❌ Traceroute error: {e}"

        print(f'Running: {" ".join(cmd)}\n')
        
        start_time = time.time()
        returncode, output = self.stream_subprocess(cmd)
        execution_time = time.time() - start_time

        result = f"🛣️ <b>Traceroute to {target}</b>\n\n"
        result += f"Command: <code>{' '.join(cmd)}</code>\n"
        result += f"Execution time: {execution_time:.2f}s\n"
        result += f"Return code: {returncode}\n\n"
        
        if len(output) > 3000:
            result += f"<code>{output[-3000:]}</code>"
        else:
            result += f"<code>{output}</code>"

        return result

    def prompt_target(self) -> Optional[str]:
        """Prompt user for target"""
        while True:
            user_input = input('Enter target IP/hostname (or "quit"): ').strip()
            if not user_input:
                print('Please enter a value.')
                continue
            if user_input.lower() in ('q', 'quit', 'exit'):
                return None

            if self.is_ipv4_or_ipv6(user_input) or self.is_valid_hostname(user_input):
                return user_input
            else:
                print('Invalid IP/hostname. Examples: 8.8.8.8, example.com')

class DatabaseManager:
    """Manage SQLite database for network data"""
    
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Original tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitored_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved BOOLEAN DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN DEFAULT 1
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS intrusion_detection (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                packet_count INTEGER,
                description TEXT,
                action_taken TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                packets_processed INTEGER,
                packet_rate REAL,
                tcp_count INTEGER,
                udp_count INTEGER,
                icmp_count INTEGER,
                threat_count INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS session_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_name TEXT NOT NULL,
                data_type TEXT NOT NULL,
                data TEXT,
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Chart data tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chart_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chart_type TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                data TEXT
            )
        ''')
        
        # Port scan results for charts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS port_scan_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                port INTEGER,
                service TEXT,
                status TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_command(self, command: str, source: str = 'local', success: bool = True):
        """Log command to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO command_history (command, source, success) VALUES (?, ?, ?)',
            (command, source, success)
        )
        conn.commit()
        conn.close()
    
    def log_intrusion(self, source_ip: str, threat_type: str, severity: str, 
                     packet_count: int = 0, description: str = "", action: str = "logged"):
        """Log intrusion detection event"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO intrusion_detection 
               (source_ip, threat_type, severity, packet_count, description, action_taken) 
               VALUES (?, ?, ?, ?, ?, ?)''',
            (source_ip, threat_type, severity, packet_count, description, action)
        )
        conn.commit()
        conn.close()
    
    def log_network_stats(self, stats: Dict[str, Any]):
        """Log network statistics"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO network_stats 
               (packets_processed, packet_rate, tcp_count, udp_count, icmp_count, threat_count)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (stats.get('packets_processed', 0),
             stats.get('packet_rate', 0),
             stats.get('tcp_count', 0),
             stats.get('udp_count', 0),
             stats.get('icmp_count', 0),
             stats.get('threat_count', 0))
        )
        conn.commit()
        conn.close()
    
    def log_threat(self, ip_address: str, threat_type: str, severity: str, 
                  description: str = "", port: int = None, protocol: str = None):
        """Log security threat to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO threat_logs 
               (ip_address, threat_type, severity, description) 
               VALUES (?, ?, ?, ?)''',
            (ip_address, threat_type, severity, description)
        )
        conn.commit()
        conn.close()
    
    def log_port_scan_data(self, ip_address: str, port_data: List[Dict]):
        """Log port scan data for charts"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        for data in port_data:
            cursor.execute(
                '''INSERT INTO port_scan_data 
                   (ip_address, port, service, status) 
                   VALUES (?, ?, ?, ?)''',
                (ip_address, data.get('port'), data.get('service'), data.get('status', 'open'))
            )
        
        conn.commit()
        conn.close()
    
    def get_port_scan_chart_data(self, ip_address: str) -> Dict[str, Any]:
        """Get port scan data for charts"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Get port distribution
        cursor.execute('''
            SELECT service, COUNT(*) as count 
            FROM port_scan_data 
            WHERE ip_address = ? AND status = 'open'
            GROUP BY service
        ''', (ip_address,))
        
        service_dist = cursor.fetchall()
        
        # Get port status
        cursor.execute('''
            SELECT status, COUNT(*) as count 
            FROM port_scan_data 
            WHERE ip_address = ?
            GROUP BY status
        ''', (ip_address,))
        
        status_dist = cursor.fetchall()
        
        # Get top ports
        cursor.execute('''
            SELECT port, service 
            FROM port_scan_data 
            WHERE ip_address = ? AND status = 'open'
            ORDER BY port
        ''', (ip_address,))
        
        ports = cursor.fetchall()
        
        conn.close()
        
        return {
            'service_distribution': dict(service_dist),
            'status_distribution': dict(status_dist),
            'ports': ports
        }
    
    def get_recent_intrusions(self, limit: int = 50) -> List[Tuple]:
        """Get recent intrusion detection events"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''SELECT timestamp, source_ip, threat_type, severity, description 
               FROM intrusion_detection 
               ORDER BY timestamp DESC LIMIT ?''',
            (limit,)
        )
        results = cursor.fetchall()
        conn.close()
        return results
    
    def get_threat_stats(self, hours: int = 24) -> Dict[str, int]:
        """Get threat statistics for specified period"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT threat_type, COUNT(*) as count 
            FROM intrusion_detection 
            WHERE timestamp > datetime('now', ?)
            GROUP BY threat_type
        ''', (f'-{hours} hours',))
        
        results = cursor.fetchall()
        conn.close()
        
        stats = {}
        for threat_type, count in results:
            stats[threat_type] = count
        
        return stats
    
    def get_network_stats_history(self, hours: int = 24) -> List[Dict]:
        """Get network stats history for charts"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, packets_processed, packet_rate, threat_count
            FROM network_stats 
            WHERE timestamp > datetime('now', ?)
            ORDER BY timestamp
        ''', (f'-{hours} hours',))
        
        results = cursor.fetchall()
        conn.close()
        
        stats_history = []
        for row in results:
            stats_history.append({
                'timestamp': row[0],
                'packets_processed': row[1],
                'packet_rate': row[2],
                'threat_count': row[3]
            })
        
        return stats_history
    
    def clear_old_data(self, days: int = 30):
        """Clear data older than specified days"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cutoff = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
        
        tables = ['intrusion_detection', 'network_stats', 'threat_logs', 'port_scan_data']
        for table in tables:
            cursor.execute(f'DELETE FROM {table} WHERE timestamp < ?', (cutoff,))
        
        conn.commit()
        conn.close()

class ThreatDetector:
    """Advanced threat detection system with real-time analysis"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.ip_stats = {}
        self.port_stats = {}
        self.syn_flood_stats = {}
        self.detection_thresholds = {
            'DOS': 1000,  # packets per second
            'PortScan': 50,  # unique ports in 60 seconds
            'SYNFlood': 500,  # SYN packets without ACK
            'UDPFlood': 1000,  # UDP packets per second
            'ICMPFlood': 500,  # ICMP packets per second
            'BruteForce': 100  # failed connection attempts
        }
        
        # Real-time stats for charts
        self.realtime_stats = {
            'packet_count': 0,
            'threat_count': 0,
            'protocol_dist': {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0},
            'threat_dist': {'DOS': 0, 'PortScan': 0, 'SYNFlood': 0, 'UDPFlood': 0, 'ICMPFlood': 0}
        }
        
    def analyze_packet(self, packet):
        """Analyze packet for threats with real-time updates"""
        threats = []
        
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            self.realtime_stats['packet_count'] += 1
            
            # Initialize stats for IP
            if ip_src not in self.ip_stats:
                self.ip_stats[ip_src] = {
                    'packet_count': 0,
                    'last_seen': time.time(),
                    'ports_accessed': set(),
                    'packet_times': [],
                    'syn_count': 0
                }
            
            ip_stat = self.ip_stats[ip_src]
            ip_stat['packet_count'] += 1
            ip_stat['last_seen'] = time.time()
            ip_stat['packet_times'].append(time.time())
            
            # Keep only last minute of packet times
            cutoff = time.time() - 60
            ip_stat['packet_times'] = [t for t in ip_stat['packet_times'] if t > cutoff]
            
            # Protocol-specific analysis
            if TCP in packet:
                self.realtime_stats['protocol_dist']['TCP'] += 1
                threats.extend(self._analyze_tcp(packet, ip_src))
            elif UDP in packet:
                self.realtime_stats['protocol_dist']['UDP'] += 1
                threats.extend(self._analyze_udp(packet, ip_src))
            elif ICMP in packet:
                self.realtime_stats['protocol_dist']['ICMP'] += 1
                threats.extend(self._analyze_icmp(packet, ip_src))
            else:
                self.realtime_stats['protocol_dist']['Other'] += 1
            
            # General threat detection
            dos_threats = self._detect_dos(ip_src)
            port_scan_threats = self._detect_port_scan(ip_src)
            
            threats.extend(dos_threats)
            threats.extend(port_scan_threats)
            
            if threats:
                self.realtime_stats['threat_count'] += len(threats)
                for threat in threats:
                    threat_type = threat['type']
                    if threat_type in self.realtime_stats['threat_dist']:
                        self.realtime_stats['threat_dist'][threat_type] += 1
        
        return threats
    
    def _analyze_tcp(self, packet, ip_src):
        """Analyze TCP packets"""
        threats = []
        tcp = packet[TCP]
        
        # Track ports accessed
        self.ip_stats[ip_src]['ports_accessed'].add(tcp.dport)
        
        # SYN flood detection
        if tcp.flags & 0x02:  # SYN flag
            self.ip_stats[ip_src]['syn_count'] += 1
            
            if ip_src not in self.syn_flood_stats:
                self.syn_flood_stats[ip_src] = {'syn_count': 0, 'start_time': time.time()}
            
            self.syn_flood_stats[ip_src]['syn_count'] += 1
            
            # Check for SYN flood
            syn_stats = self.syn_flood_stats[ip_src]
            elapsed = time.time() - syn_stats['start_time']
            if elapsed > 0:
                syn_rate = syn_stats['syn_count'] / elapsed
                if syn_rate > self.detection_thresholds['SYNFlood']:
                    threats.append({
                        'type': 'SYNFlood',
                        'source': ip_src,
                        'severity': 'high',
                        'rate': syn_rate
                    })
        
        return threats
    
    def _analyze_udp(self, packet, ip_src):
        """Analyze UDP packets"""
        threats = []
        udp = packet[UDP]
        
        # Track UDP packet rate
        udp_rate = len([t for t in self.ip_stats[ip_src]['packet_times'] 
                       if time.time() - t < 1])
        
        if udp_rate > self.detection_thresholds['UDPFlood']:
            threats.append({
                'type': 'UDPFlood',
                'source': ip_src,
                'severity': 'medium',
                'rate': udp_rate
            })
        
        return threats
    
    def _analyze_icmp(self, packet, ip_src):
        """Analyze ICMP packets"""
        threats = []
        
        # Track ICMP packet rate
        icmp_rate = len([t for t in self.ip_stats[ip_src]['packet_times'] 
                        if time.time() - t < 1])
        
        if icmp_rate > self.detection_thresholds['ICMPFlood']:
            threats.append({
                'type': 'ICMPFlood',
                'source': ip_src,
                'severity': 'medium',
                'rate': icmp_rate
            })
        
        return threats
    
    def _detect_dos(self, ip_src):
        """Detect DOS attacks"""
        threats = []
        
        ip_stat = self.ip_stats[ip_src]
        if len(ip_stat['packet_times']) > 0:
            time_window = ip_stat['packet_times'][-1] - ip_stat['packet_times'][0]
            if time_window > 0:
                packet_rate = len(ip_stat['packet_times']) / time_window
                if packet_rate > self.detection_thresholds['DOS']:
                    threats.append({
                        'type': 'DOS',
                        'source': ip_src,
                        'severity': 'high',
                        'rate': packet_rate
                    })
        
        return threats
    
    def _detect_port_scan(self, ip_src):
        """Detect port scanning"""
        threats = []
        
        ip_stat = self.ip_stats[ip_src]
        unique_ports = len(ip_stat['ports_accessed'])
        
        if unique_ports > self.detection_thresholds['PortScan']:
            threats.append({
                'type': 'PortScan',
                'source': ip_src,
                'severity': 'medium',
                'ports': unique_ports
            })
        
        return threats
    
    def get_realtime_stats(self) -> Dict[str, Any]:
        """Get real-time statistics for charts"""
        return self.realtime_stats.copy()
    
    def clear_old_stats(self, max_age: int = 300):
        """Clear statistics older than max_age seconds"""
        cutoff = time.time() - max_age
        ips_to_remove = []
        
        for ip, stats in self.ip_stats.items():
            if stats['last_seen'] < cutoff:
                ips_to_remove.append(ip)
        
        for ip in ips_to_remove:
            del self.ip_stats[ip]
            
        # Clean SYN flood stats
        syn_ips_to_remove = []
        for ip, stats in self.syn_flood_stats.items():
            if stats['start_time'] < cutoff:
                syn_ips_to_remove.append(ip)
        
        for ip in syn_ips_to_remove:
            del self.syn_flood_stats[ip]

class NetworkMonitor:
    """Network monitoring with threat detection and chart support"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.threat_detector = ThreatDetector(db_manager)
        self.is_monitoring = False
        self.sniffer_thread = None
        self.packet_queue = queue.Queue()
        self.target_ip = None
        self.packet_count = 0
        self.start_time = None
        self.stats = {
            'tcp_count': 0,
            'udp_count': 0,
            'icmp_count': 0,
            'threat_count': 0,
            'unique_ips': set()
        }
        
        # Chart data
        self.chart_data = {
            'packet_history': [],
            'threat_history': [],
            'protocol_history': [],
            'timestamps': []
        }
    
    def start_monitoring(self, target_ip: str = None):
        """Start network monitoring"""
        if self.is_monitoring:
            return False
        
        self.target_ip = target_ip
        self.is_monitoring = True
        self.packet_count = 0
        self.start_time = time.time()
        self.stats = {'tcp_count': 0, 'udp_count': 0, 'icmp_count': 0, 'threat_count': 0, 'unique_ips': set()}
        
        # Reset chart data
        self.chart_data = {
            'packet_history': [],
            'threat_history': [],
            'protocol_history': [],
            'timestamps': []
        }
        
        # Start packet capture thread
        self.sniffer_thread = threading.Thread(
            target=self._packet_capture_loop,
            daemon=True
        )
        self.sniffer_thread.start()
        
        # Start packet processing thread
        self.processor_thread = threading.Thread(
            target=self._packet_processing_loop,
            daemon=True
        )
        self.processor_thread.start()
        
        # Start stats logging thread
        self.stats_thread = threading.Thread(
            target=self._stats_logging_loop,
            daemon=True
        )
        self.stats_thread.start()
        
        return True
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.is_monitoring = False
        
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=2)
        if self.processor_thread and self.processor_thread.is_alive():
            self.processor_thread.join(timeout=2)
        if self.stats_thread and self.stats_thread.is_alive():
            self.stats_thread.join(timeout=2)
    
    def _packet_capture_loop(self):
        """Capture packets from network"""
        try:
            filter_str = f"host {self.target_ip}" if self.target_ip else ""
            sniff(
                filter=filter_str,
                prn=lambda p: self.packet_queue.put(p),
                store=0,
                stop_filter=lambda _: not self.is_monitoring
            )
        except Exception as e:
            print(f"Packet capture error: {e}")
    
    def _packet_processing_loop(self):
        """Process captured packets for threats"""
        while self.is_monitoring or not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get(timeout=1)
                self.packet_count += 1
                
                # Update protocol stats
                if IP in packet:
                    self.stats['unique_ips'].add(packet[IP].src)
                    
                    if TCP in packet:
                        self.stats['tcp_count'] += 1
                    elif UDP in packet:
                        self.stats['udp_count'] += 1
                    elif ICMP in packet:
                        self.stats['icmp_count'] += 1
                
                # Detect threats
                threats = self.threat_detector.analyze_packet(packet)
                if threats:
                    self.stats['threat_count'] += len(threats)
                    for threat in threats:
                        self.db_manager.log_intrusion(
                            source_ip=threat['source'],
                            threat_type=threat['type'],
                            severity=threat['severity'],
                            description=f"Rate: {threat.get('rate', 'N/A')}"
                        )
                        self.db_manager.log_threat(
                            ip_address=threat['source'],
                            threat_type=threat['type'],
                            severity=threat['severity'],
                            description=f"Rate: {threat.get('rate', 'N/A')}"
                        )
                
                # Update chart data every 10 packets
                if self.packet_count % 10 == 0:
                    self._update_chart_data()
                
                # Clean old stats periodically
                if self.packet_count % 1000 == 0:
                    self.threat_detector.clear_old_stats()
                    
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Packet processing error: {e}")
    
    def _update_chart_data(self):
        """Update chart data with current statistics"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        # Keep only last 50 data points
        if len(self.chart_data['timestamps']) > 50:
            self.chart_data['timestamps'].pop(0)
            self.chart_data['packet_history'].pop(0)
            self.chart_data['threat_history'].pop(0)
            self.chart_data['protocol_history'].pop(0)
        
        self.chart_data['timestamps'].append(timestamp)
        self.chart_data['packet_history'].append(self.packet_count)
        self.chart_data['threat_history'].append(self.stats['threat_count'])
        
        # Protocol distribution
        total_protocols = self.stats['tcp_count'] + self.stats['udp_count'] + self.stats['icmp_count']
        if total_protocols > 0:
            protocol_dist = {
                'TCP': (self.stats['tcp_count'] / total_protocols) * 100,
                'UDP': (self.stats['udp_count'] / total_protocols) * 100,
                'ICMP': (self.stats['icmp_count'] / total_protocols) * 100
            }
            self.chart_data['protocol_history'].append(protocol_dist)
    
    def _stats_logging_loop(self):
        """Periodically log network statistics"""
        while self.is_monitoring:
            time.sleep(60)  # Log every minute
            
            uptime = time.time() - self.start_time
            if uptime > 0:
                stats = {
                    'packets_processed': self.packet_count,
                    'packet_rate': self.packet_count / uptime,
                    'tcp_count': self.stats['tcp_count'],
                    'udp_count': self.stats['udp_count'],
                    'icmp_count': self.stats['icmp_count'],
                    'threat_count': self.stats['threat_count']
                }
                self.db_manager.log_network_stats(stats)
    
    def get_current_stats(self) -> Dict[str, Any]:
        """Get current monitoring statistics"""
        uptime = time.time() - self.start_time if self.start_time else 0
        packet_rate = self.packet_count / uptime if uptime > 0 else 0
        
        return {
            'is_monitoring': self.is_monitoring,
            'target_ip': self.target_ip,
            'packets_processed': self.packet_count,
            'unique_ips': len(self.stats['unique_ips']),
            'uptime': uptime,
            'packet_rate': packet_rate,
            'tcp_packets': self.stats['tcp_count'],
            'udp_packets': self.stats['udp_count'],
            'icmp_packets': self.stats['icmp_count'],
            'threats_detected': self.stats['threat_count']
        }
    
    def get_chart_data(self) -> Dict[str, Any]:
        """Get chart data for visualization"""
        return {
            'timestamps': self.chart_data['timestamps'],
            'packet_history': self.chart_data['packet_history'],
            'threat_history': self.chart_data['threat_history'],
            'protocol_history': self.chart_data['protocol_history'],
            'realtime_stats': self.threat_detector.get_realtime_stats()
        }

class NetworkScanner:
    """Network scanning capabilities with chart support"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.traceroute_tool = TracerouteTool()
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        else:
            self.nm = None
    
    def ping_ip(self, ip: str) -> str:
        """Comprehensive ping with analysis"""
        try:
            # Validate IP address
            try:
                socket.inet_aton(ip)
            except socket.error:
                return f"❌ Invalid IP address: {ip}"
            
            # Method 1: Using system ping command
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, "4", ip]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                response = f"✅ {ip} is reachable\n\n"
                
                # Extract ping statistics
                lines = result.stdout.split('\n')
                for line in lines:
                    if "time=" in line or "time<" in line:
                        response += f"  Response: {line.strip()}\n"
                
                # Additional network analysis
                response += self.analyze_network_health(ip)
                return response
            else:
                return f"❌ {ip} is not reachable"
                
        except subprocess.TimeoutExpired:
            return f"❌ Ping timeout for {ip}"
        except Exception as e:
            return f"❌ Ping error: {str(e)}"
    
    def analyze_network_health(self, ip_address: str) -> str:
        """Perform additional network health analysis"""
        response = ""
        try:
            # DNS resolution test
            start_time = time.time()
            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
                dns_time = time.time() - start_time
                response += f"  DNS Resolution: {hostname} ({dns_time:.3f}s)\n"
            except:
                response += "  DNS Resolution: Failed\n"
            
            # Port connectivity quick test
            common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995]
            open_ports = []
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip_address, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
            
            if open_ports:
                response += f"  Open common ports: {open_ports}\n"
            else:
                response += "  No common ports open\n"
                
        except Exception as e:
            response += f"  Network health analysis error: {e}\n"
        
        return response
    
    def scan_ip(self, ip: str) -> Dict[str, Any]:
        """Quick port scan on common ports with chart data"""
        try:
            common_ports = [21, 22, 23, 25, 53, 80, 110, 113, 135, 139, 143, 443, 
                          445, 993, 995, 1723, 3306, 3389, 5900, 8080]
            
            results = {
                'success': True,
                'ip': ip,
                'scan_time': datetime.now().isoformat(),
                'open_ports': [],
                'services': {},
                'port_data': []
            }
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    
                    if result == 0:
                        service_name = self.get_service_name(port)
                        results['open_ports'].append(port)
                        results['services'][port] = service_name
                        results['port_data'].append({
                            'port': port,
                            'service': service_name,
                            'status': 'open'
                        })
                    else:
                        results['port_data'].append({
                            'port': port,
                            'service': self.get_service_name(port),
                            'status': 'closed'
                        })
                        
                except Exception:
                    continue
            
            # Log port scan data for charts
            self.db_manager.log_port_scan_data(ip, results['port_data'])
            
            return results
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def deep_scan_ip(self, ip: str) -> Dict[str, Any]:
        """Comprehensive port scan (1-65535)"""
        if not self.nm:
            return {'success': False, 'error': 'Nmap not available'}
        
        try:
            self.nm.scan(ip, '1-65535', arguments='-sS -T4')
            
            if ip in self.nm.all_hosts():
                host = self.nm[ip]
                results = {
                    'success': True,
                    'ip': ip,
                    'scan_time': datetime.now().isoformat(),
                    'state': host.state(),
                    'open_ports': [],
                    'services': {},
                    'port_data': []
                }
                
                for proto in host.all_protocols():
                    ports = host[proto].keys()
                    for port in ports:
                        service_info = host[proto][port]
                        results['open_ports'].append(port)
                        results['services'][port] = {
                            'name': service_info.get('name', 'unknown'),
                            'product': service_info.get('product', ''),
                            'version': service_info.get('version', ''),
                            'state': service_info.get('state', '')
                        }
                        results['port_data'].append({
                            'port': port,
                            'service': service_info.get('name', 'unknown'),
                            'status': service_info.get('state', 'unknown')
                        })
                
                # Log port scan data for charts
                self.db_manager.log_port_scan_data(ip, results['port_data'])
                
                return results
            else:
                return {'success': False, 'error': f'Host {ip} not found in scan results'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_service_name(self, port: int) -> str:
        """Get service name for common ports"""
        service_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 113: "Ident", 135: "RPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy"
        }
        return service_map.get(port, "Unknown")
    
    def traceroute(self, target: str) -> str:
        """Perform enhanced traceroute"""
        return self.traceroute_tool.interactive_traceroute(target)
    
    def port_scan(self, ip: str, ports: str = "1-1000") -> Dict[str, Any]:
        """Perform port scan using nmap with chart data"""
        if self.nm:
            try:
                self.nm.scan(ip, ports, arguments='-T4')
                open_ports = []
                port_data = []
                
                if ip in self.nm.all_hosts():
                    for proto in self.nm[ip].all_protocols():
                        lport = self.nm[ip][proto].keys()
                        for port in lport:
                            state = self.nm[ip][proto][port]['state']
                            service = self.nm[ip][proto][port].get('name', 'unknown')
                            
                            if state == 'open':
                                open_ports.append({
                                    'port': port,
                                    'state': state,
                                    'service': service
                                })
                            
                            port_data.append({
                                'port': port,
                                'service': service,
                                'status': state
                            })
                
                # Log to database for charts
                self.db_manager.log_port_scan_data(ip, port_data)
                
                return {
                    'success': True,
                    'target': ip,
                    'open_ports': open_ports,
                    'port_data': port_data,
                    'scan_time': datetime.now().isoformat()
                }
            except Exception as e:
                return {'success': False, 'error': str(e)}
        else:
            return {'success': False, 'error': 'Nmap not available'}
    
    def get_ip_location(self, ip: str) -> str:
        """Get IP location using ip-api.com and ipinfo.io"""
        try:
            location_data = {}
            
            # Try ipapi.co first
            try:
                response = requests.get(f"http://ipapi.co/{ip}/json/", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if 'error' not in data:
                        location_data = {
                            'country': data.get('country_name', 'Unknown'),
                            'region': data.get('region', 'Unknown'),
                            'city': data.get('city', 'Unknown'),
                            'isp': data.get('org', 'Unknown'),
                            'timezone': data.get('timezone', 'Unknown'),
                            'coordinates': f"{data.get('latitude', 'Unknown')}, {data.get('longitude', 'Unknown')}"
                        }
            except:
                pass
            
            # If ipapi.co fails, try ipinfo.io
            if not location_data:
                try:
                    response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        location_data = {
                            'country': data.get('country', 'Unknown'),
                            'region': data.get('region', 'Unknown'),
                            'city': data.get('city', 'Unknown'),
                            'isp': data.get('org', 'Unknown'),
                            'timezone': data.get('timezone', 'Unknown'),
                            'coordinates': data.get('loc', 'Unknown')
                        }
                except:
                    pass
            
            if location_data:
                result = f"📍 Location information for {ip}:\n"
                for key, value in location_data.items():
                    result += f"  {key.title()}: {value}\n"
                return result
            else:
                return "❌ Unable to retrieve location information"
                
        except Exception as e:
            return f"❌ Location lookup error: {str(e)}"
    
    def vulnerability_scan(self, target: str) -> Dict[str, Any]:
        """Perform vulnerability scan"""
        if not self.nm:
            return {'success': False, 'error': 'Nmap not available'}
        
        try:
            self.nm.scan(target, arguments='--script vuln')
            
            vulns = []
            if target in self.nm.all_hosts():
                for script in self.nm[target].get('scripts', []):
                    if 'vuln' in script.lower():
                        vulns.append(script)
            
            return {
                'success': True,
                'target': target,
                'vulnerabilities': vulns,
                'scan_time': datetime.now().isoformat()
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

class NetworkTrafficGenerator:
    """Network traffic generation capabilities"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.running = False
        self.current_thread = None
    
    def generate_tcp_traffic(self, target_ip: str, port: int, packet_count: int, delay: float) -> str:
        """Generate TCP traffic"""
        if not SCAPY_AVAILABLE:
            return "❌ Scapy not available for TCP traffic generation"
        
        try:
            packets_sent = 0
            start_time = time.time()
            
            for i in range(packet_count):
                if not self.running:
                    break
                
                src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
                packet = IP(src=src_ip, dst=target_ip)/TCP(sport=random.randint(1024, 65535), dport=port)
                send(packet, verbose=0)
                packets_sent += 1
                
                if delay > 0:
                    time.sleep(delay)
            
            duration = time.time() - start_time
            
            # Log to database
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO traffic_logs (traffic_type, target, packets_sent, duration) VALUES (?, ?, ?, ?)',
                ('TCP Flood', f"{target_ip}:{port}", packets_sent, duration)
            )
            conn.commit()
            conn.close()
            
            return f"✅ Sent {packets_sent} TCP packets to {target_ip}:{port} in {duration:.2f}s"
            
        except Exception as e:
            return f"❌ TCP traffic error: {str(e)}"
    
    def generate_udp_traffic(self, target_ip: str, port: int, packet_count: int, delay: float) -> str:
        """Generate UDP traffic"""
        if not SCAPY_AVAILABLE:
            return "❌ Scapy not available for UDP traffic generation"
        
        try:
            packets_sent = 0
            start_time = time.time()
            
            for i in range(packet_count):
                if not self.running:
                    break
                
                src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
                payload = random._urandom(random.randint(64, 512))
                packet = IP(src=src_ip, dst=target_ip)/UDP(sport=random.randint(1024, 65535), dport=port)/payload
                send(packet, verbose=0)
                packets_sent += 1
                
                if delay > 0:
                    time.sleep(delay)
            
            duration = time.time() - start_time
            
            # Log to database
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO traffic_logs (traffic_type, target, packets_sent, duration) VALUES (?, ?, ?, ?)',
                ('UDP Flood', f"{target_ip}:{port}", packets_sent, duration)
            )
            conn.commit()
            conn.close()
            
            return f"✅ Sent {packets_sent} UDP packets to {target_ip}:{port} in {duration:.2f}s"
            
        except Exception as e:
            return f"❌ UDP traffic error: {str(e)}"
    
    def generate_icmp_traffic(self, target_ip: str, packet_count: int, delay: float) -> str:
        """Generate ICMP traffic"""
        if not SCAPY_AVAILABLE:
            return "❌ Scapy not available for ICMP traffic generation"
        
        try:
            packets_sent = 0
            start_time = time.time()
            
            for i in range(packet_count):
                if not self.running:
                    break
                
                packet = IP(dst=target_ip)/ICMP()
                send(packet, verbose=0)
                packets_sent += 1
                
                if delay > 0:
                    time.sleep(delay)
            
            duration = time.time() - start_time
            
            # Log to database
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO traffic_logs (traffic_type, target, packets_sent, duration) VALUES (?, ?, ?, ?)',
                ('ICMP Flood', target_ip, packets_sent, duration)
            )
            conn.commit()
            conn.close()
            
            return f"✅ Sent {packets_sent} ICMP packets to {target_ip} in {duration:.2f}s"
            
        except Exception as e:
            return f"❌ ICMP traffic error: {str(e)}"
    
    def kill_ip(self, ip_address: str):
        """Generate traffic to stress test IP (use responsibly)"""
        try:
            # Send various types of traffic
            threads = []
            
            # ICMP flood
            icmp_thread = threading.Thread(target=self._icmp_flood, args=(ip_address,))
            threads.append(icmp_thread)
            
            # TCP SYN flood
            tcp_thread = threading.Thread(target=self._tcp_syn_flood, args=(ip_address,))
            threads.append(tcp_thread)
            
            # UDP flood
            udp_thread = threading.Thread(target=self._udp_flood, args=(ip_address,))
            threads.append(udp_thread)
            
            for thread in threads:
                thread.daemon = True
                thread.start()
            
            # Run for 30 seconds
            time.sleep(30)
            
            return f"✅ Traffic generation to {ip_address} completed"
            
        except Exception as e:
            return f"❌ Traffic generation error: {str(e)}"
    
    def _icmp_flood(self, ip_address: str):
        """Generate ICMP flood"""
        try:
            packet = IP(dst=ip_address)/ICMP()
            for _ in range(1000):  # Limited for safety
                send(packet, verbose=0)
                time.sleep(0.01)
        except Exception:
            pass
    
    def _tcp_syn_flood(self, ip_address: str):
        """Generate TCP SYN flood"""
        try:
            for port in range(80, 90):  # Limited port range
                packet = IP(dst=ip_address)/TCP(dport=port, flags='S')
                for _ in range(100):  # Limited for safety
                    send(packet, verbose=0)
                    time.sleep(0.01)
        except Exception:
            pass
    
    def _udp_flood(self, ip_address: str):
        """Generate UDP flood"""
        try:
            packet = IP(dst=ip_address)/UDP(dport=53)
            for _ in range(1000):  # Limited for safety
                send(packet, verbose=0)
                time.sleep(0.01)
        except Exception:
            pass
    
    def stop_traffic(self):
        """Stop all traffic generation"""
        self.running = False
        if self.current_thread and self.current_thread.is_alive():
            self.current_thread.join(timeout=2)

class TelegramManager:
    """Telegram integration manager with enhanced features"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.telegram_token = None
        self.telegram_chat_id = None
        self.telegram_last_update_id = 0
        self.telegram_enabled = False
        self.bot_username = None
        self.commands_registered = False
        self.load_config()
    
    def load_config(self):
        """Load Telegram configuration"""
        config = configparser.ConfigParser()
        if os.path.exists(DEFAULT_CONFIG_FILE):
            config.read(DEFAULT_CONFIG_FILE)
            self.telegram_token = config.get('telegram', 'token', fallback=None)
            self.telegram_chat_id = config.get('telegram', 'chat_id', fallback=None)
            if self.telegram_token and self.telegram_chat_id:
                self.telegram_enabled = True
    
    def save_config(self):
        """Save Telegram configuration"""
        config = configparser.ConfigParser()
        config['telegram'] = {
            'token': self.telegram_token or '',
            'chat_id': self.telegram_chat_id or ''
        }
        with open(DEFAULT_CONFIG_FILE, 'w') as configfile:
            config.write(configfile)
    
    def config_telegram_token(self, token: str):
        """Configure Telegram bot token"""
        try:
            self.telegram_token = token
            self.save_config()
            
            # Test the token
            if self.test_telegram_token(token):
                self.telegram_enabled = True
                self.register_bot_commands()
                return "✅ Telegram token configured successfully"
            else:
                self.telegram_enabled = False
                return "❌ Invalid Telegram token"
                
        except Exception as e:
            return f"❌ Failed to configure token: {str(e)}"
    
    def config_telegram_chat_id(self, chat_id: str):
        """Configure Telegram chat ID"""
        try:
            self.telegram_chat_id = chat_id
            self.save_config()
            
            if self.telegram_token and self.test_telegram_token(self.telegram_token):
                self.telegram_enabled = True
                return "✅ Telegram chat ID configured successfully"
            else:
                return "⚠ Telegram token not configured or invalid"
                
        except Exception as e:
            return f"❌ Failed to configure chat ID: {str(e)}"
    
    def test_telegram_token(self, token: str = None) -> bool:
        """Test Telegram token validity"""
        try:
            test_token = token or self.telegram_token
            if not test_token:
                return False
                
            response = requests.get(
                f"{TELEGRAM_API_URL}{test_token}/getMe",
                timeout=10
            )
            
            if response.status_code == 200:
                bot_info = response.json()
                if bot_info.get('ok', False):
                    self.bot_username = bot_info['result']['username']
                    return True
            return False
            
        except Exception:
            return False
    
    def register_bot_commands(self):
        """Register bot commands with Telegram"""
        if not self.telegram_token:
            return
        
        commands = [
            {"command": "start", "description": "Start the bot"},
            {"command": "help", "description": "Show help message"},
            {"command": "ping", "description": "Ping an IP address"},
            {"command": "scan", "description": "Scan IP for open ports"},
            {"command": "traceroute", "description": "Trace route to target"},
            {"command": "status", "description": "Get system status"},
            {"command": "threats", "description": "Show recent threats"},
            {"command": "location", "description": "Get IP location"},
            {"command": "monitor", "description": "Start monitoring IP"},
            {"command": "stop", "description": "Stop monitoring"}
        ]
        
        try:
            url = f"{TELEGRAM_API_URL}{self.telegram_token}/setMyCommands"
            response = requests.post(url, json={"commands": commands}, timeout=10)
            self.commands_registered = response.status_code == 200
        except Exception:
            pass
    
    def test_telegram_connection(self) -> str:
        """Test Telegram connection"""
        try:
            if not self.telegram_token or not self.telegram_chat_id:
                return "❌ Telegram token or chat ID not configured"
            
            # Test bot token
            response = requests.get(
                f"{TELEGRAM_API_URL}{self.telegram_token}/getMe",
                timeout=10
            )
            
            if response.status_code == 200:
                bot_info = response.json()
                if bot_info['ok']:
                    result = "✅ Telegram connection successful\n"
                    result += f"  Bot: {bot_info['result']['first_name']}\n"
                    result += f"  Username: @{bot_info['result']['username']}"
                    
                    # Test message sending
                    if self.send_telegram_message("🔒 Cyber Security Tool - Connection Test Successful!"):
                        result += "\n✅ Test message sent successfully"
                        self.telegram_enabled = True
                        self.register_bot_commands()
                    else:
                        result += "\n❌ Failed to send test message"
                        self.telegram_enabled = False
                    return result
                else:
                    self.telegram_enabled = False
                    return "❌ Telegram connection failed"
            else:
                self.telegram_enabled = False
                return f"❌ Telegram API error: {response.status_code}"
                
        except Exception as e:
            self.telegram_enabled = False
            return f"❌ Telegram connection test failed: {str(e)}"
    
    def send_telegram_message(self, message: str, parse_mode: str = 'HTML') -> bool:
        """Send message to Telegram chat"""
        try:
            if not self.telegram_token or not self.telegram_chat_id:
                return False
            
            url = f"{TELEGRAM_API_URL}{self.telegram_token}/sendMessage"
            payload = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': parse_mode,
                'disable_web_page_preview': True
            }
            
            response = requests.post(url, json=payload, timeout=10)
            
            # Log the message
            if response.status_code == 200:
                conn = sqlite3.connect(DATABASE_FILE)
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO telegram_logs (timestamp, chat_id, message, direction) VALUES (?, ?, ?, ?)",
                    (datetime.now().isoformat(), self.telegram_chat_id, message, 'outgoing')
                )
                conn.commit()
                conn.close()
            
            return response.status_code == 200
            
        except Exception:
            return False
    
    def send_telegram_photo(self, photo_path: str, caption: str = "") -> bool:
        """Send photo to Telegram chat"""
        try:
            if not self.telegram_token or not self.telegram_chat_id:
                return False
            
            url = f"{TELEGRAM_API_URL}{self.telegram_token}/sendPhoto"
            
            with open(photo_path, 'rb') as photo:
                files = {'photo': photo}
                data = {'chat_id': self.telegram_chat_id, 'caption': caption}
                response = requests.post(url, files=files, data=data, timeout=30)
            
            return response.status_code == 200
            
        except Exception:
            return False
    
    def process_telegram_updates(self):
        """Process incoming Telegram messages"""
        if not self.telegram_enabled:
            return
        
        try:
            url = f"{TELEGRAM_API_URL}{self.telegram_token}/getUpdates"
            params = {'offset': self.telegram_last_update_id + 1, 'timeout': 30}
            
            response = requests.get(url, params=params, timeout=35)
            
            if response.status_code == 200:
                data = response.json()
                if data['ok'] and 'result' in data:
                    for update in data['result']:
                        self.telegram_last_update_id = update['update_id']
                        if 'message' in update and 'text' in update['message']:
                            self.process_message(update['message'])
        except Exception as e:
            print(f"Telegram update error: {e}")
    
    def process_message(self, message):
        """Process individual message"""
        text = message['text']
        chat_id = message['chat']['id']
        
        if not self.telegram_chat_id:
            self.telegram_chat_id = str(chat_id)
            self.save_config()
        
        self.db_manager.log_command(text, 'telegram', True)
        
        # Basic command processing
        if text.startswith('/'):
            parts = text.split()
            command = parts[0].lower()
            
            response = "Unknown command. Use /help for available commands."
            
            if command == '/start':
                response = self.get_start_message()
            elif command == '/help':
                response = self.get_help_message()
            elif command == '/status':
                response = self.get_status_message()
            
            self.send_telegram_message(response)
    
    def get_start_message(self) -> str:
        """Get start message for Telegram"""
        return """
🔒 <b>Accurate Cyber Defense Bot v3.0</b> 🔒

Welcome to the ultimate cyber security monitoring tool!

<b>Available Commands:</b>
/start - Start the bot
/help - Show all commands
/ping [IP] - Ping an IP address
/scan [IP] - Scan IP for open ports
/traceroute [IP] - Trace route to target
/status - Get system status
/threats - Show recent threats
/location [IP] - Get IP location
/monitor [IP] - Start monitoring IP
/stop - Stop monitoring

<b>Example:</b>
<code>/ping 8.8.8.8</code>
<code>/scan 192.168.1.1</code>
<code>/location 1.1.1.1</code>
        """
    
    def get_help_message(self) -> str:
        """Get help message for Telegram"""
        return """
📚 <b>Command Reference</b>

<b>Network Tools:</b>
<code>/ping [IP]</code> - Ping an IP address
<code>/scan [IP]</code> - Scan IP for open ports
<code>/traceroute [IP]</code> - Trace route to target
<code>/location [IP]</code> - Get IP location info

<b>Monitoring:</b>
<code>/monitor [IP]</code> - Start monitoring IP
<code>/stop</code> - Stop all monitoring
<code>/status</code> - Get system status
<code>/threats</code> - Show recent threats

<b>System:</b>
<code>/help</code> - Show this message
<code>/start</code> - Start the bot

<b>Examples:</b>
<code>/ping 192.168.1.1</code>
<code>/scan 8.8.8.8</code>
<code>/traceroute google.com</code>
        """
    
    def get_status_message(self) -> str:
        """Get status message for Telegram"""
        cpu = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        status = f"""
📊 <b>System Status</b>

<b>System Info:</b>
OS: {platform.system()} {platform.release()}
CPU: {cpu}%
Memory: {memory.percent}%
Disk: {disk.percent}%

<b>Network:</b>
Hostname: {socket.gethostname()}
IP: {socket.gethostbyname(socket.gethostname())}

<b>Bot Status:</b>
✅ Online
Version: {VERSION}
        """
        
        return status
    
    def get_telegram_status(self) -> str:
        """Get Telegram connection status"""
        status = "Telegram Status:\n"
        status += f"  Enabled: {'✅ Yes' if self.telegram_enabled else '❌ No'}\n"
        status += f"  Bot Token: {'✅ Configured' if self.telegram_token else '❌ Not Configured'}\n"
        status += f"  Chat ID: {'✅ Configured' if self.telegram_chat_id else '❌ Not Configured'}"
        
        if self.telegram_token and self.telegram_chat_id:
            if self.test_telegram_token():
                status += "\n  Bot token: ✅ Valid"
                if self.bot_username:
                    status += f"\n  Bot username: @{self.bot_username}"
            else:
                status += "\n  Bot token: ❌ Invalid"
        
        return status
    
    def export_data(self) -> str:
        """Export data to Telegram"""
        try:
            if not self.telegram_enabled:
                return "❌ Telegram not configured or enabled"
            
            # Create export package
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                export_data = {
                    'export_time': datetime.now().isoformat(),
                    'system_status': "OPERATIONAL",
                    'telegram_messages': {
                        'incoming': 0,
                        'outgoing': 0
                    }
                }
                
                # Get message counts
                conn = sqlite3.connect(DATABASE_FILE)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM telegram_logs WHERE direction = 'incoming'")
                export_data['telegram_messages']['incoming'] = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM telegram_logs WHERE direction = 'outgoing'")
                export_data['telegram_messages']['outgoing'] = cursor.fetchone()[0]
                conn.close()
                
                json.dump(export_data, f, indent=2)
                temp_file = f.name
            
            # Send file via Telegram
            url = f"{TELEGRAM_API_URL}{self.telegram_token}/sendDocument"
            with open(temp_file, 'rb') as document:
                response = requests.post(
                    url,
                    data={'chat_id': self.telegram_chat_id, 'caption': '📊 System Data Export'},
                    files={'document': document}
                )
            
            # Clean up
            os.unlink(temp_file)
            
            if response.status_code == 200:
                return "✅ Data exported to Telegram successfully"
            else:
                return "❌ Failed to export data to Telegram"
                
        except Exception as e:
            return f"❌ Export failed: {str(e)}"

class ChartManager:
    """Manage chart creation and visualization"""
    
    def __init__(self, theme: str = "dark"):
        self.theme = theme
        self.colors = {
            'dark': {
                'bg': '#1a1a1a',
                'text': '#ffffff',
                'grid': '#333333',
                'bars': ['#00ff00', '#ffff00', '#ff0000', '#00ffff', '#ff00ff'],
                'pie': ['#00ff00', '#ffff00', '#ff0000', '#00ffff', '#ff00ff', '#0000ff']
            },
            'light': {
                'bg': '#ffffff',
                'text': '#000000',
                'grid': '#dddddd',
                'bars': ['#006600', '#666600', '#660000', '#006666', '#660066'],
                'pie': ['#006600', '#666600', '#660000', '#006666', '#660066', '#000066']
            },
            'cyber': {
                'bg': '#0f0f25',
                'text': '#00ffff',
                'grid': '#252545',
                'bars': ['#00ff00', '#ffff00', '#ff0000', '#00ffff', '#ff00ff'],
                'pie': ['#00ff00', '#ffff00', '#ff0000', '#00ffff', '#ff00ff', '#0000ff']
            }
        }
    
    def create_packet_distribution_chart(self, protocol_data: Dict[str, int], title: str = "Packet Distribution"):
        """Create pie chart for packet distribution"""
        if not MATPLOTLIB_AVAILABLE:
            return None
        
        fig, ax = plt.subplots(figsize=(6, 4))
        
        # Prepare data
        labels = list(protocol_data.keys())
        sizes = list(protocol_data.values())
        colors = self.colors[self.theme]['pie'][:len(labels)]
        
        # Create pie chart
        wedges, texts, autotexts = ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                                         startangle=90, shadow=True)
        
        # Style the chart
        ax.set_title(title, color=self.colors[self.theme]['text'], fontsize=12, fontweight='bold')
        fig.patch.set_facecolor(self.colors[self.theme]['bg'])
        ax.set_facecolor(self.colors[self.theme]['bg'])
        
        # Style text
        for text in texts:
            text.set_color(self.colors[self.theme]['text'])
        for autotext in autotexts:
            autotext.set_color(self.colors[self.theme]['text'])
        
        ax.axis('equal')  # Equal aspect ratio ensures pie is drawn as circle
        plt.tight_layout()
        
        return fig
    
    def create_threat_distribution_chart(self, threat_data: Dict[str, int], title: str = "Threat Distribution"):
        """Create bar chart for threat distribution"""
        if not MATPLOTLIB_AVAILABLE:
            return None
        
        fig, ax = plt.subplots(figsize=(8, 5))
        
        # Prepare data
        threats = list(threat_data.keys())
        counts = list(threat_data.values())
        colors = self.colors[self.theme]['bars'][:len(threats)]
        
        # Create bar chart
        bars = ax.bar(threats, counts, color=colors, edgecolor='white', linewidth=1)
        
        # Add count labels on bars
        for bar, count in zip(bars, counts):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                   f'{count}', ha='center', va='bottom', color=self.colors[self.theme]['text'])
        
        # Style the chart
        ax.set_title(title, color=self.colors[self.theme]['text'], fontsize=12, fontweight='bold')
        ax.set_xlabel('Threat Type', color=self.colors[self.theme]['text'])
        ax.set_ylabel('Count', color=self.colors[self.theme]['text'])
        ax.set_facecolor(self.colors[self.theme]['bg'])
        fig.patch.set_facecolor(self.colors[self.theme]['bg'])
        
        # Style ticks
        ax.tick_params(axis='x', colors=self.colors[self.theme]['text'], rotation=45)
        ax.tick_params(axis='y', colors=self.colors[self.theme]['text'])
        
        # Style grid
        ax.grid(True, color=self.colors[self.theme]['grid'], linestyle='--', alpha=0.3)
        
        plt.tight_layout()
        
        return fig
    
    def create_port_scan_chart(self, port_data: Dict[str, Any], title: str = "Port Scan Results"):
        """Create chart for port scan results"""
        if not MATPLOTLIB_AVAILABLE:
            return None
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
        
        # Service distribution pie chart
        service_data = port_data.get('service_distribution', {})
        if service_data:
            labels = list(service_data.keys())
            sizes = list(service_data.values())
            colors = self.colors[self.theme]['pie'][:len(labels)]
            
            wedges, texts, autotexts = ax1.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                                              startangle=90)
            ax1.set_title('Service Distribution', color=self.colors[self.theme]['text'])
            
            for text in texts:
                text.set_color(self.colors[self.theme]['text'])
            for autotext in autotexts:
                autotext.set_color(self.colors[self.theme]['text'])
        
        # Port status bar chart
        status_data = port_data.get('status_distribution', {})
        if status_data:
            statuses = list(status_data.keys())
            counts = list(status_data.values())
            colors = ['#00ff00' if s == 'open' else '#ff0000' for s in statuses]
            
            bars = ax2.bar(statuses, counts, color=colors, edgecolor='white', linewidth=1)
            ax2.set_title('Port Status', color=self.colors[self.theme]['text'])
            ax2.set_xlabel('Status', color=self.colors[self.theme]['text'])
            ax2.set_ylabel('Count', color=self.colors[self.theme]['text'])
            
            for bar, count in zip(bars, counts):
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                        f'{count}', ha='center', va='bottom', color=self.colors[self.theme]['text'])
        
        # Style both subplots
        for ax in [ax1, ax2]:
            ax.set_facecolor(self.colors[self.theme]['bg'])
        
        fig.suptitle(title, color=self.colors[self.theme]['text'], fontsize=14, fontweight='bold')
        fig.patch.set_facecolor(self.colors[self.theme]['bg'])
        
        plt.tight_layout()
        
        return fig
    
    def create_real_time_chart(self, chart_data: Dict[str, List], title: str = "Real-time Network Traffic"):
        """Create real-time line chart"""
        if not MATPLOTLIB_AVAILABLE:
            return None
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))
        
        # Packet history line chart
        timestamps = chart_data.get('timestamps', [])
        packet_history = chart_data.get('packet_history', [])
        threat_history = chart_data.get('threat_history', [])
        
        if timestamps and packet_history:
            ax1.plot(timestamps, packet_history, color='#00ff00', linewidth=2, marker='o', markersize=4)
            ax1.set_title('Packet Count Over Time', color=self.colors[self.theme]['text'])
            ax1.set_ylabel('Packets', color=self.colors[self.theme]['text'])
            ax1.fill_between(timestamps, packet_history, alpha=0.3, color='#00ff00')
        
        if timestamps and threat_history:
            ax2.plot(timestamps, threat_history, color='#ff0000', linewidth=2, marker='s', markersize=4)
            ax2.set_title('Threat Count Over Time', color=self.colors[self.theme]['text'])
            ax2.set_xlabel('Time', color=self.colors[self.theme]['text'])
            ax2.set_ylabel('Threats', color=self.colors[self.theme]['text'])
            ax2.fill_between(timestamps, threat_history, alpha=0.3, color='#ff0000')
        
        # Style both subplots
        for ax in [ax1, ax2]:
            ax.set_facecolor(self.colors[self.theme]['bg'])
            ax.tick_params(axis='x', colors=self.colors[self.theme]['text'], rotation=45)
            ax.tick_params(axis='y', colors=self.colors[self.theme]['text'])
            ax.grid(True, color=self.colors[self.theme]['grid'], linestyle='--', alpha=0.3)
        
        fig.suptitle(title, color=self.colors[self.theme]['text'], fontsize=14, fontweight='bold')
        fig.patch.set_facecolor(self.colors[self.theme]['bg'])
        
        plt.tight_layout()
        
        return fig
    
    def save_chart(self, fig, filename: str):
        """Save chart to file"""
        if fig:
            fig.savefig(filename, facecolor=self.colors[self.theme]['bg'], dpi=150)
            plt.close(fig)
    
    def set_theme(self, theme: str):
        """Set chart theme"""
        if theme in self.colors:
            self.theme = theme

class CyberSecurityDashboard:
    """Main GUI dashboard for cyber security monitoring with advanced charts"""
    
    def __init__(self, root, db_manager: DatabaseManager, 
                 network_monitor: NetworkMonitor, network_scanner: NetworkScanner,
                 telegram_manager: TelegramManager):
        self.root = root
        self.db_manager = db_manager
        self.monitor = network_monitor
        self.scanner = network_scanner
        self.telegram_manager = telegram_manager
        self.current_theme = "dark"
        self.chart_manager = ChartManager(self.current_theme)
        
        # Chart update interval
        self.chart_update_interval = 2000  # ms
        
        # Chart figures
        self.chart_figures = {}
        
        self.setup_gui()
        self.update_interval = 2000  # ms
        self.update_dashboard()
    
    def setup_gui(self):
        """Setup the main dashboard GUI"""
        self.root.title(f"Accurate Cyber Defense v{VERSION} - Ultimate Edition")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 800)
        
        # Create menu
        self.create_menu()
        
        # Create main frame with paned window
        self.main_paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.main_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left panel for controls and stats
        self.left_panel = ttk.Frame(self.main_paned)
        self.main_paned.add(self.left_panel, weight=1)
        
        # Right panel for charts
        self.right_panel = ttk.Frame(self.main_paned)
        self.main_paned.add(self.right_panel, weight=2)
        
        # Setup left panel
        self.setup_left_panel()
        
        # Setup right panel with notebook for charts
        self.setup_right_panel()
        
        # Apply theme
        self.apply_theme()
    
    def create_menu(self):
        """Create application menu"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Session", command=self.new_session)
        file_menu.add_command(label="Load Session", command=self.load_session)
        file_menu.add_command(label="Save Session", command=self.save_session)
        file_menu.add_separator()
        file_menu.add_command(label="Export Charts", command=self.export_charts)
        file_menu.add_command(label="Generate Report", command=self.generate_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Dark Theme", command=lambda: self.switch_theme("dark"))
        view_menu.add_command(label="Light Theme", command=lambda: self.switch_theme("light"))
        view_menu.add_command(label="Cyber Theme", command=lambda: self.switch_theme("cyber"))
        view_menu.add_separator()
        view_menu.add_command(label="Refresh Charts", command=self.refresh_charts)
        view_menu.add_command(label="Clear Chart Data", command=self.clear_chart_data)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Traffic Generator", command=self.open_traffic_generator)
        tools_menu.add_command(label="Port Scanner", command=self.open_port_scanner)
        tools_menu.add_command(label="Vulnerability Scanner", command=self.open_vulnerability_scanner)
        tools_menu.add_command(label="Network Analyzer", command=self.open_network_analyzer)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Telegram menu
        telegram_menu = tk.Menu(menubar, tearoff=0)
        telegram_menu.add_command(label="Configure Telegram", command=self.configure_telegram)
        telegram_menu.add_command(label="Test Connection", command=self.test_telegram_connection)
        telegram_menu.add_command(label="Send Test Message", command=self.send_telegram_test)
        telegram_menu.add_command(label="Export to Telegram", command=self.export_to_telegram)
        menubar.add_cascade(label="Telegram", menu=telegram_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="User Guide", command=self.show_user_guide)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def setup_left_panel(self):
        """Setup left panel with controls and stats"""
        # Create notebook for left panel
        self.left_notebook = ttk.Notebook(self.left_panel)
        self.left_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Control tab
        self.control_tab = ttk.Frame(self.left_notebook)
        self.left_notebook.add(self.control_tab, text="Controls")
        self.setup_control_tab()
        
        # Stats tab
        self.stats_tab = ttk.Frame(self.left_notebook)
        self.left_notebook.add(self.stats_tab, text="Statistics")
        self.setup_stats_tab()
        
        # Threats tab
        self.threats_tab = ttk.Frame(self.left_notebook)
        self.left_notebook.add(self.threats_tab, text="Threats")
        self.setup_threats_tab()
        
        # Terminal tab
        self.terminal_tab = ttk.Frame(self.left_notebook)
        self.left_notebook.add(self.terminal_tab, text="Terminal")
        self.setup_terminal_tab()
    
    def setup_control_tab(self):
        """Setup control tab"""
        # Monitoring controls
        monitor_frame = ttk.LabelFrame(self.control_tab, text="Network Monitoring")
        monitor_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Target IP
        ttk.Label(monitor_frame, text="Target IP:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.monitor_ip_entry = ttk.Entry(monitor_frame, width=20)
        self.monitor_ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Interface selection
        ttk.Label(monitor_frame, text="Interface:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.interface_var = tk.StringVar()
        interfaces = self.get_network_interfaces()
        self.interface_combo = ttk.Combobox(monitor_frame, textvariable=self.interface_var, values=interfaces, state="readonly")
        self.interface_combo.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        if interfaces:
            self.interface_var.set(interfaces[0])
        
        # Control buttons
        button_frame = ttk.Frame(monitor_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        self.start_btn = ttk.Button(button_frame, text="Start Monitoring", command=self.start_monitoring, width=15)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="Stop Monitoring", command=self.stop_monitoring, width=15, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Network tools
        tools_frame = ttk.LabelFrame(self.control_tab, text="Network Tools")
        tools_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Scan target
        ttk.Label(tools_frame, text="Scan Target:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.scan_target_entry = ttk.Entry(tools_frame, width=20)
        self.scan_target_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Port range
        ttk.Label(tools_frame, text="Ports:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.port_range_entry = ttk.Entry(tools_frame, width=20)
        self.port_range_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        self.port_range_entry.insert(0, "1-1000")
        
        # Tool buttons
        tools_button_frame = ttk.Frame(tools_frame)
        tools_button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        # First row of buttons
        row1_frame = ttk.Frame(tools_button_frame)
        row1_frame.pack(pady=2)
        
        ttk.Button(row1_frame, text="Ping", command=self.run_ping, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1_frame, text="Port Scan", command=self.run_port_scan, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1_frame, text="Deep Scan", command=self.run_deep_scan, width=12).pack(side=tk.LEFT, padx=2)
        
        # Second row of buttons
        row2_frame = ttk.Frame(tools_button_frame)
        row2_frame.pack(pady=2)
        
        ttk.Button(row2_frame, text="Traceroute", command=self.run_traceroute, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(row2_frame, text="Vuln Scan", command=self.run_vuln_scan, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(row2_frame, text="Get Location", command=self.get_location, width=12).pack(side=tk.LEFT, padx=2)
        
        # Third row of buttons
        row3_frame = ttk.Frame(tools_button_frame)
        row3_frame.pack(pady=2)
        
        ttk.Button(row3_frame, text="Analyze IP", command=self.run_analyze, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(row3_frame, text="Traffic Gen", command=self.open_traffic_generator, width=12).pack(side=tk.LEFT, padx=2)
        
        # System info
        system_frame = ttk.LabelFrame(self.control_tab, text="System Information")
        system_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.system_info_text = scrolledtext.ScrolledText(system_frame, height=6, wrap=tk.WORD)
        self.system_info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.system_info_text.config(state=tk.DISABLED)
    
    def setup_stats_tab(self):
        """Setup statistics tab"""
        # Real-time stats
        stats_frame = ttk.LabelFrame(self.stats_tab, text="Real-time Statistics")
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create stats display grid
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.stats_labels = {}
        stats_config = [
            ("Packets Processed:", "packets"),
            ("Packet Rate:", "rate"),
            ("TCP Packets:", "tcp"),
            ("UDP Packets:", "udp"),
            ("ICMP Packets:", "icmp"),
            ("Threats Detected:", "threats"),
            ("Unique IPs:", "unique_ips"),
            ("Monitoring Time:", "uptime")
        ]
        
        for i, (label_text, key) in enumerate(stats_config):
            row = i // 2
            col = i % 2
            
            frame = ttk.Frame(stats_grid)
            frame.grid(row=row, column=col, sticky=tk.W, padx=10, pady=8)
            
            ttk.Label(frame, text=label_text, font=('Arial', 9, 'bold')).pack(side=tk.LEFT)
            self.stats_labels[key] = ttk.Label(frame, text="0", font=('Arial', 9, 'bold'), foreground="#00ff00")
            self.stats_labels[key].pack(side=tk.LEFT, padx=5)
        
        # Protocol distribution
        protocol_frame = ttk.LabelFrame(self.stats_tab, text="Protocol Distribution")
        protocol_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.protocol_text = scrolledtext.ScrolledText(protocol_frame, height=4, wrap=tk.WORD)
        self.protocol_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.protocol_text.config(state=tk.DISABLED)
    
    def setup_threats_tab(self):
        """Setup threats tab"""
        # Threat log
        threat_frame = ttk.LabelFrame(self.threats_tab, text="Threat Log")
        threat_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create treeview for threats
        columns = ('Time', 'Source IP', 'Threat Type', 'Severity', 'Description')
        self.threats_tree = ttk.Treeview(threat_frame, columns=columns, show='headings', height=15)
        
        # Define headings
        for col in columns:
            self.threats_tree.heading(col, text=col)
            self.threats_tree.column(col, width=100, minwidth=50)
        
        # Add scrollbars
        tree_scroll_y = ttk.Scrollbar(threat_frame, orient=tk.VERTICAL, command=self.threats_tree.yview)
        tree_scroll_x = ttk.Scrollbar(threat_frame, orient=tk.HORIZONTAL, command=self.threats_tree.xview)
        self.threats_tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)
        
        # Grid layout
        self.threats_tree.grid(row=0, column=0, sticky=tk.NSEW)
        tree_scroll_y.grid(row=0, column=1, sticky=tk.NS)
        tree_scroll_x.grid(row=1, column=0, sticky=tk.EW)
        
        # Configure grid weights
        threat_frame.grid_rowconfigure(0, weight=1)
        threat_frame.grid_columnconfigure(0, weight=1)
        
        # Threat statistics
        stats_frame = ttk.LabelFrame(self.threats_tab, text="Threat Statistics")
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.threat_stats_text = scrolledtext.ScrolledText(stats_frame, height=6, wrap=tk.WORD)
        self.threat_stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.threat_stats_text.config(state=tk.DISABLED)
    
    def setup_terminal_tab(self):
        """Setup terminal tab"""
        # Terminal output
        terminal_frame = ttk.LabelFrame(self.terminal_tab, text="Command Terminal")
        terminal_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.terminal_output = scrolledtext.ScrolledText(terminal_frame, wrap=tk.WORD, height=15)
        self.terminal_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.terminal_output.config(state=tk.DISABLED)
        
        # Terminal input
        input_frame = ttk.Frame(terminal_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        ttk.Label(input_frame, text=">").pack(side=tk.LEFT, padx=5)
        self.terminal_input = ttk.Entry(input_frame)
        self.terminal_input.pack(fill=tk.X, expand=True, padx=5, side=tk.LEFT)
        self.terminal_input.bind('<Return>', self.execute_terminal_command)
        
        # Help button
        ttk.Button(input_frame, text="Help", command=self.show_terminal_help, width=10).pack(side=tk.RIGHT, padx=5)
    
    def setup_right_panel(self):
        """Setup right panel with charts"""
        # Create notebook for charts
        self.chart_notebook = ttk.Notebook(self.right_panel)
        self.chart_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Real-time charts tab
        self.realtime_chart_tab = ttk.Frame(self.chart_notebook)
        self.chart_notebook.add(self.realtime_chart_tab, text="Real-time Charts")
        self.setup_realtime_charts()
        
        # Port scan charts tab
        self.port_scan_chart_tab = ttk.Frame(self.chart_notebook)
        self.chart_notebook.add(self.port_scan_chart_tab, text="Port Scan Charts")
        self.setup_port_scan_charts()
        
        # Threat charts tab
        self.threat_chart_tab = ttk.Frame(self.chart_notebook)
        self.chart_notebook.add(self.threat_chart_tab, text="Threat Charts")
        self.setup_threat_charts()
        
        # System charts tab
        self.system_chart_tab = ttk.Frame(self.chart_notebook)
        self.chart_notebook.add(self.system_chart_tab, text="System Charts")
        self.setup_system_charts()
    
    def setup_realtime_charts(self):
        """Setup real-time charts"""
        # Create frame for real-time charts
        realtime_frame = ttk.Frame(self.realtime_chart_tab)
        realtime_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Packet traffic chart
        packet_frame = ttk.LabelFrame(realtime_frame, text="Packet Traffic Over Time")
        packet_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.packet_fig = Figure(figsize=(8, 4), dpi=100)
        self.packet_ax = self.packet_fig.add_subplot(111)
        self.packet_canvas = FigureCanvasTkAgg(self.packet_fig, packet_frame)
        self.packet_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Threat detection chart
        threat_frame = ttk.LabelFrame(realtime_frame, text="Threat Detection Over Time")
        threat_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.threat_fig = Figure(figsize=(8, 4), dpi=100)
        self.threat_ax = self.threat_fig.add_subplot(111)
        self.threat_canvas = FigureCanvasTkAgg(self.threat_fig, threat_frame)
        self.threat_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def setup_port_scan_charts(self):
        """Setup port scan charts"""
        # Create frame for port scan charts
        port_frame = ttk.Frame(self.port_scan_chart_tab)
        port_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Service distribution chart
        service_frame = ttk.LabelFrame(port_frame, text="Service Distribution")
        service_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.service_fig = Figure(figsize=(8, 6), dpi=100)
        self.service_ax = self.service_fig.add_subplot(111)
        self.service_canvas = FigureCanvasTkAgg(self.service_fig, service_frame)
        self.service_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Port status chart
        status_frame = ttk.LabelFrame(port_frame, text="Port Status Distribution")
        status_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.status_fig = Figure(figsize=(8, 4), dpi=100)
        self.status_ax = self.status_fig.add_subplot(111)
        self.status_canvas = FigureCanvasTkAgg(self.status_fig, status_frame)
        self.status_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def setup_threat_charts(self):
        """Setup threat charts"""
        # Create frame for threat charts
        threat_frame = ttk.Frame(self.threat_chart_tab)
        threat_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Threat type distribution
        type_frame = ttk.LabelFrame(threat_frame, text="Threat Type Distribution")
        type_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.threat_type_fig = Figure(figsize=(8, 6), dpi=100)
        self.threat_type_ax = self.threat_type_fig.add_subplot(111)
        self.threat_type_canvas = FigureCanvasTkAgg(self.threat_type_fig, type_frame)
        self.threat_type_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Threat severity chart
        severity_frame = ttk.LabelFrame(threat_frame, text="Threat Severity Distribution")
        severity_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.severity_fig = Figure(figsize=(8, 4), dpi=100)
        self.severity_ax = self.severity_fig.add_subplot(111)
        self.severity_canvas = FigureCanvasTkAgg(self.severity_fig, severity_frame)
        self.severity_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def setup_system_charts(self):
        """Setup system charts"""
        # Create frame for system charts
        system_frame = ttk.Frame(self.system_chart_tab)
        system_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # CPU and Memory usage
        usage_frame = ttk.LabelFrame(system_frame, text="System Resource Usage")
        usage_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.usage_fig = Figure(figsize=(8, 6), dpi=100)
        self.usage_ax = self.usage_fig.add_subplot(111)
        self.usage_canvas = FigureCanvasTkAgg(self.usage_fig, usage_frame)
        self.usage_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Network connections
        conn_frame = ttk.LabelFrame(system_frame, text="Network Connections")
        conn_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.conn_fig = Figure(figsize=(8, 4), dpi=100)
        self.conn_ax = self.conn_fig.add_subplot(111)
        self.conn_canvas = FigureCanvasTkAgg(self.conn_fig, conn_frame)
        self.conn_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def apply_theme(self):
        """Apply current theme to GUI"""
        theme = THEMES[self.current_theme]
        self.chart_manager.set_theme(self.current_theme)
        
        # Configure ttk styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('.', background=theme['bg'], foreground=theme['fg'])
        style.configure('TFrame', background=theme['bg'])
        style.configure('TLabel', background=theme['bg'], foreground=theme['fg'])
        style.configure('TLabelframe', background=theme['bg'], foreground=theme['fg'])
        style.configure('TLabelframe.Label', background=theme['bg'], foreground=theme['fg'])
        style.configure('TButton', background=theme['button_bg'], foreground=theme['button_fg'])
        style.configure('TEntry', fieldbackground=theme['text_bg'], foreground=theme['text_fg'])
        style.configure('TCombobox', fieldbackground=theme['text_bg'], foreground=theme['text_fg'])
        style.configure('TNotebook', background=theme['bg'])
        style.configure('TNotebook.Tab', background=theme['button_bg'], foreground=theme['button_fg'])
        
        # Configure text widgets
        text_widgets = [self.system_info_text, self.protocol_text, 
                       self.threat_stats_text, self.terminal_output]
        
        for widget in text_widgets:
            widget.configure(
                background=theme['text_bg'],
                foreground=theme['text_fg'],
                insertbackground=theme['fg']
            )
        
        # Configure treeview
        style.configure('Treeview', 
                       background=theme['text_bg'],
                       foreground=theme['text_fg'],
                       fieldbackground=theme['text_bg'])
        style.map('Treeview', background=[('selected', theme['highlight'])])
    
    def switch_theme(self, theme: str):
        """Switch to specified theme"""
        if theme in THEMES:
            self.current_theme = theme
            self.apply_theme()
            self.refresh_charts()
    
    def get_network_interfaces(self):
        """Get available network interfaces"""
        try:
            interfaces = netifaces.interfaces()
            return [iface for iface in interfaces if iface != 'lo' and not iface.startswith('docker')]
        except:
            return ['eth0', 'wlan0', 'en0', 'en1']
    
    def start_monitoring(self):
        """Start network monitoring"""
        target_ip = self.monitor_ip_entry.get().strip()
        interface = self.interface_var.get()
        
        if target_ip and not self.validate_ip(target_ip):
            messagebox.showerror("Error", "Invalid IP address")
            return
        
        if self.monitor.start_monitoring(target_ip):
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.log_message(f"Started monitoring {target_ip if target_ip else 'all traffic'} on interface {interface}")
        else:
            messagebox.showwarning("Warning", "Monitoring is already active")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitor.stop_monitoring()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log_message("Stopped network monitoring")
    
    def run_ping(self):
        """Run ping command"""
        target = self.scan_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.terminal_output.config(state=tk.NORMAL)
        self.terminal_output.insert(tk.END, f"Pinging {target}...\n")
        self.terminal_output.config(state=tk.DISABLED)
        self.terminal_output.see(tk.END)
        
        def do_ping():
            result = self.scanner.ping_ip(target)
            self.terminal_output.config(state=tk.NORMAL)
            self.terminal_output.insert(tk.END, result + "\n")
            self.terminal_output.config(state=tk.DISABLED)
            self.terminal_output.see(tk.END)
        
        threading.Thread(target=do_ping, daemon=True).start()
    
    def run_port_scan(self):
        """Run port scan"""
        target = self.scan_target_entry.get().strip()
        ports = self.port_range_entry.get().strip()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        if not self.validate_ip(target):
            messagebox.showerror("Error", "Invalid IP address")
            return
        
        self.terminal_output.config(state=tk.NORMAL)
        self.terminal_output.insert(tk.END, f"Scanning {target} ports {ports}...\n")
        self.terminal_output.config(state=tk.DISABLED)
        self.terminal_output.see(tk.END)
        
        def do_scan():
            result = self.scanner.port_scan(target, ports)
            self.terminal_output.config(state=tk.NORMAL)
            
            if result['success']:
                open_ports = result.get('open_ports', [])
                self.terminal_output.insert(tk.END, f"\nScan completed. Open ports: {len(open_ports)}\n")
                for port in open_ports:
                    self.terminal_output.insert(tk.END, 
                        f"Port {port['port']}: {port['service']}\n")
                
                # Update port scan charts
                self.update_port_scan_charts(target)
            else:
                self.terminal_output.insert(tk.END, f"Error: {result.get('error', 'Unknown')}\n")
            
            self.terminal_output.config(state=tk.DISABLED)
            self.terminal_output.see(tk.END)
        
        threading.Thread(target=do_scan, daemon=True).start()
    
    def run_deep_scan(self):
        """Run deep scan"""
        target = self.scan_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.terminal_output.config(state=tk.NORMAL)
        self.terminal_output.insert(tk.END, f"Deep scanning {target}...\n")
        self.terminal_output.config(state=tk.DISABLED)
        self.terminal_output.see(tk.END)
        
        def do_deep_scan():
            result = self.scanner.deep_scan_ip(target)
            self.terminal_output.config(state=tk.NORMAL)
            
            if result['success']:
                open_ports = result.get('open_ports', [])
                self.terminal_output.insert(tk.END, f"\nDeep scan completed. Open ports: {len(open_ports)}\n")
                for port in open_ports[:20]:  # Show first 20 ports
                    service_info = result['services'].get(port, {})
                    name = service_info.get('name', 'unknown')
                    product = service_info.get('product', '')
                    version = service_info.get('version', '')
                    self.terminal_output.insert(tk.END, 
                        f"Port {port}: {name} {product} {version}\n".strip() + "\n")
                
                # Update port scan charts
                self.update_port_scan_charts(target)
            else:
                self.terminal_output.insert(tk.END, f"Error: {result.get('error', 'Unknown')}\n")
            
            self.terminal_output.config(state=tk.DISABLED)
            self.terminal_output.see(tk.END)
        
        threading.Thread(target=do_deep_scan, daemon=True).start()
    
    def run_traceroute(self):
        """Run traceroute"""
        target = self.scan_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.terminal_output.config(state=tk.NORMAL)
        self.terminal_output.insert(tk.END, f"Traceroute to {target}...\n")
        self.terminal_output.config(state=tk.DISABLED)
        self.terminal_output.see(tk.END)
        
        def do_trace():
            result = self.scanner.traceroute(target)
            self.terminal_output.config(state=tk.NORMAL)
            self.terminal_output.insert(tk.END, result + "\n")
            self.terminal_output.config(state=tk.DISABLED)
            self.terminal_output.see(tk.END)
        
        threading.Thread(target=do_trace, daemon=True).start()
    
    def run_vuln_scan(self):
        """Run vulnerability scan"""
        target = self.scan_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        if not NMAP_AVAILABLE:
            messagebox.showerror("Error", "Nmap not available")
            return
        
        self.terminal_output.config(state=tk.NORMAL)
        self.terminal_output.insert(tk.END, f"Running vulnerability scan on {target}...\n")
        self.terminal_output.config(state=tk.DISABLED)
        self.terminal_output.see(tk.END)
        
        def do_vuln_scan():
            result = self.scanner.vulnerability_scan(target)
            self.terminal_output.config(state=tk.NORMAL)
            
            if result['success']:
                vulns = result.get('vulnerabilities', [])
                self.terminal_output.insert(tk.END, f"\nVulnerabilities found: {len(vulns)}\n")
                for vuln in vulns:
                    self.terminal_output.insert(tk.END, f"• {vuln}\n")
            else:
                self.terminal_output.insert(tk.END, f"Error: {result.get('error', 'Unknown')}\n")
            
            self.terminal_output.config(state=tk.DISABLED)
            self.terminal_output.see(tk.END)
        
        threading.Thread(target=do_vuln_scan, daemon=True).start()
    
    def get_location(self):
        """Get IP location"""
        target = self.scan_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.terminal_output.config(state=tk.NORMAL)
        self.terminal_output.insert(tk.END, f"Getting location for {target}...\n")
        self.terminal_output.config(state=tk.DISABLED)
        self.terminal_output.see(tk.END)
        
        def do_location():
            result = self.scanner.get_ip_location(target)
            self.terminal_output.config(state=tk.NORMAL)
            self.terminal_output.insert(tk.END, result + "\n")
            self.terminal_output.config(state=tk.DISABLED)
            self.terminal_output.see(tk.END)
        
        threading.Thread(target=do_location, daemon=True).start()
    
    def run_analyze(self):
        """Run deep analysis"""
        target = self.scan_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.terminal_output.config(state=tk.NORMAL)
        self.terminal_output.insert(tk.END, f"Analyzing {target}...\n")
        self.terminal_output.config(state=tk.DISABLED)
        self.terminal_output.see(tk.END)
        
        def do_analyse():
            self.terminal_output.config(state=tk.NORMAL)
            
            # Ping
            self.terminal_output.insert(tk.END, "1. Ping Test:\n")
            self.terminal_output.insert(tk.END, self.scanner.ping_ip(target) + "\n\n")
            
            # Quick Scan
            self.terminal_output.insert(tk.END, "2. Quick Port Scan:\n")
            result = self.scanner.scan_ip(target)
            if result['success']:
                self.terminal_output.insert(tk.END, f"   Open ports: {len(result.get('open_ports', []))}\n")
                # Update port scan charts
                self.update_port_scan_charts(target)
            else:
                self.terminal_output.insert(tk.END, "   Scan failed\n")
            
            # Location
            self.terminal_output.insert(tk.END, "\n3. Location Information:\n")
            self.terminal_output.insert(tk.END, self.scanner.get_ip_location(target))
            
            self.terminal_output.config(state=tk.DISABLED)
            self.terminal_output.see(tk.END)
        
        threading.Thread(target=do_analyse, daemon=True).start()
    
    def execute_terminal_command(self, event=None):
        """Execute terminal command"""
        command = self.terminal_input.get()
        self.terminal_input.delete(0, tk.END)
        
        if not command:
            return
        
        # Display command
        self.terminal_output.config(state=tk.NORMAL)
        self.terminal_output.insert(tk.END, f"> {command}\n")
        
        # Execute command
        if command.lower() == 'help':
            help_text = """
Available Commands:
  ping [ip]              - Ping IP address
  tracert [ip]           - Traceroute (Windows)
  traceroute [ip]        - Traceroute (Linux/Mac)
  scan [ip]              - Port scan
  deepscan [ip]          - Deep port scan
  vulnscan [ip]          - Vulnerability scan
  location [ip]          - Get IP location
  analyze [ip]           - Analyze IP
  
  start [ip]            - Start monitoring IP
  stop                  - Stop monitoring
  status                - Show system status
  threats               - Show threats
  clear                 - Clear terminal
  help                  - Show this help
            """
            self.terminal_output.insert(tk.END, help_text + "\n")
        
        elif command.lower().startswith('ping '):
            ip = command[5:].strip()
            result = self.scanner.ping_ip(ip)
            self.terminal_output.insert(tk.END, result + "\n")
        
        elif command.lower().startswith('scan '):
            ip = command[5:].strip()
            result = self.scanner.scan_ip(ip)
            if result['success']:
                self.terminal_output.insert(tk.END, f"Open ports: {len(result.get('open_ports', []))}\n")
            else:
                self.terminal_output.insert(tk.END, f"Error: {result.get('error', 'Unknown')}\n")
        
        elif command.lower() == 'status':
            stats = self.monitor.get_current_stats()
            status = f"Monitoring: {'Active' if stats['is_monitoring'] else 'Inactive'}\n"
            status += f"Packets: {stats['packets_processed']}\n"
            status += f"Threats: {stats['threats_detected']}\n"
            status += f"Unique IPs: {stats['unique_ips']}\n"
            self.terminal_output.insert(tk.END, status + "\n")
        
        elif command.lower() == 'threats':
            threats = self.db_manager.get_recent_intrusions(10)
            if threats:
                self.terminal_output.insert(tk.END, "Recent Threats:\n")
                for timestamp, source_ip, threat_type, severity, description in threats:
                    self.terminal_output.insert(tk.END, f"{timestamp} - {source_ip} - {threat_type} ({severity})\n")
            else:
                self.terminal_output.insert(tk.END, "No threats detected\n")
        
        elif command.lower() == 'clear':
            self.terminal_output.config(state=tk.NORMAL)
            self.terminal_output.delete(1.0, tk.END)
            self.terminal_output.config(state=tk.DISABLED)
            return
        
        else:
            self.terminal_output.insert(tk.END, f"Unknown command: {command}\n")
        
        self.terminal_output.see(tk.END)
        self.terminal_output.config(state=tk.DISABLED)
    
    def show_terminal_help(self):
        """Show terminal help"""
        help_text = """
Terminal Commands:
  ping [ip]              - Ping IP address
  tracert [ip]           - Traceroute (Windows)
  traceroute [ip]        - Traceroute (Linux/Mac)
  scan [ip]              - Port scan
  deepscan [ip]          - Deep port scan
  vulnscan [ip]          - Vulnerability scan
  location [ip]          - Get IP location
  analyze [ip]           - Analyze IP
  
  start [ip]            - Start monitoring IP
  stop                  - Stop monitoring
  status                - Show system status
  threats               - Show threats
  clear                 - Clear terminal
  help                  - Show this help
  
Use the buttons above for more advanced features!
        """
        
        self.terminal_output.config(state=tk.NORMAL)
        self.terminal_output.insert(tk.END, help_text + "\n")
        self.terminal_output.see(tk.END)
        self.terminal_output.config(state=tk.DISABLED)
    
    def update_dashboard(self):
        """Update dashboard with current information"""
        # Update stats
        self.update_stats()
        
        # Update threats
        self.update_threats()
        
        # Update system info
        self.update_system_info()
        
        # Update charts
        self.update_charts()
        
        # Schedule next update
        self.root.after(self.update_interval, self.update_dashboard)
    
    def update_stats(self):
        """Update statistics display"""
        stats = self.monitor.get_current_stats()
        
        # Update labels
        self.stats_labels['packets'].config(text=f"{stats['packets_processed']:,}")
        self.stats_labels['rate'].config(text=f"{stats['packet_rate']:.2f}/s")
        self.stats_labels['tcp'].config(text=f"{stats['tcp_packets']:,}")
        self.stats_labels['udp'].config(text=f"{stats['udp_packets']:,}")
        self.stats_labels['icmp'].config(text=f"{stats['icmp_packets']:,}")
        self.stats_labels['threats'].config(text=f"{stats['threats_detected']:,}")
        self.stats_labels['unique_ips'].config(text=f"{stats['unique_ips']:,}")
        
        # Format uptime
        if stats['uptime'] > 0:
            hours = int(stats['uptime'] // 3600)
            minutes = int((stats['uptime'] % 3600) // 60)
            seconds = int(stats['uptime'] % 60)
            uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        else:
            uptime_str = "00:00:00"
        
        self.stats_labels['uptime'].config(text=uptime_str)
        
        # Update protocol distribution
        total = stats['tcp_packets'] + stats['udp_packets'] + stats['icmp_packets']
        if total > 0:
            protocol_text = f"TCP: {stats['tcp_packets']:,} ({(stats['tcp_packets']/total)*100:.1f}%)\n"
            protocol_text += f"UDP: {stats['udp_packets']:,} ({(stats['udp_packets']/total)*100:.1f}%)\n"
            protocol_text += f"ICMP: {stats['icmp_packets']:,} ({(stats['icmp_packets']/total)*100:.1f}%)\n"
            protocol_text += f"Total: {total:,} packets"
            
            self.protocol_text.config(state=tk.NORMAL)
            self.protocol_text.delete(1.0, tk.END)
            self.protocol_text.insert(tk.END, protocol_text)
            self.protocol_text.config(state=tk.DISABLED)
    
    def update_threats(self):
        """Update threat display"""
        # Update threat tree
        for item in self.threats_tree.get_children():
            self.threats_tree.delete(item)
        
        threats = self.db_manager.get_recent_intrusions(20)
        
        for timestamp, source_ip, threat_type, severity, description in threats:
            self.threats_tree.insert('', 'end', values=(
                timestamp,
                source_ip,
                threat_type,
                severity,
                description[:50] + "..." if len(description) > 50 else description
            ))
        
        # Update threat statistics
        threat_stats = self.db_manager.get_threat_stats(1)  # Last hour
        
        stats_text = "Threat Statistics (Last Hour):\n"
        stats_text += "-" * 30 + "\n"
        
        if threat_stats:
            for threat_type, count in threat_stats.items():
                stats_text += f"{threat_type}: {count}\n"
        else:
            stats_text += "No threats detected\n"
        
        self.threat_stats_text.config(state=tk.NORMAL)
        self.threat_stats_text.delete(1.0, tk.END)
        self.threat_stats_text.insert(tk.END, stats_text)
        self.threat_stats_text.config(state=tk.DISABLED)
    
    def update_system_info(self):
        """Update system information"""
        cpu = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        info_text = f"OS: {platform.system()} {platform.release()}\n"
        info_text += f"CPU: {cpu}%\n"
        info_text += f"Memory: {memory.percent}%\n"
        info_text += f"Disk: {disk.percent}%\n"
        info_text += f"Hostname: {socket.gethostname()}\n"
        
        try:
            connections = len(psutil.net_connections())
            info_text += f"Connections: {connections}\n"
        except:
            pass
        
        self.system_info_text.config(state=tk.NORMAL)
        self.system_info_text.delete(1.0, tk.END)
        self.system_info_text.insert(tk.END, info_text)
        self.system_info_text.config(state=tk.DISABLED)
    
    def update_charts(self):
        """Update all charts"""
        if self.monitor.is_monitoring:
            # Get chart data
            chart_data = self.monitor.get_chart_data()
            
            # Update real-time charts
            self.update_realtime_charts(chart_data)
            
            # Update threat charts
            self.update_threat_charts()
            
            # Update system charts
            self.update_system_charts()
    
    def update_realtime_charts(self, chart_data: Dict[str, Any]):
        """Update real-time charts"""
        if not MATPLOTLIB_AVAILABLE:
            return
        
        # Update packet traffic chart
        timestamps = chart_data.get('timestamps', [])
        packet_history = chart_data.get('packet_history', [])
        
        if timestamps and packet_history:
            self.packet_ax.clear()
            self.packet_ax.plot(timestamps, packet_history, 'g-', linewidth=2)
            self.packet_ax.set_title('Packet Traffic Over Time', color='white')
            self.packet_ax.set_xlabel('Time', color='white')
            self.packet_ax.set_ylabel('Packets', color='white')
            self.packet_ax.tick_params(colors='white')
            self.packet_ax.grid(True, color='gray', linestyle='--', alpha=0.3)
            self.packet_ax.set_facecolor('#1a1a1a')
            self.packet_fig.patch.set_facecolor('#1a1a1a')
            self.packet_canvas.draw()
        
        # Update threat detection chart
        threat_history = chart_data.get('threat_history', [])
        
        if timestamps and threat_history:
            self.threat_ax.clear()
            self.threat_ax.plot(timestamps, threat_history, 'r-', linewidth=2)
            self.threat_ax.set_title('Threat Detection Over Time', color='white')
            self.threat_ax.set_xlabel('Time', color='white')
            self.threat_ax.set_ylabel('Threats', color='white')
            self.threat_ax.tick_params(colors='white')
            self.threat_ax.grid(True, color='gray', linestyle='--', alpha=0.3)
            self.threat_ax.set_facecolor('#1a1a1a')
            self.threat_fig.patch.set_facecolor('#1a1a1a')
            self.threat_canvas.draw()
    
    def update_port_scan_charts(self, ip_address: str):
        """Update port scan charts"""
        if not MATPLOTLIB_AVAILABLE:
            return
        
        # Get port scan data
        port_data = self.db_manager.get_port_scan_chart_data(ip_address)
        
        # Update service distribution chart
        service_data = port_data.get('service_distribution', {})
        
        if service_data:
            self.service_ax.clear()
            labels = list(service_data.keys())
            sizes = list(service_data.values())
            colors = ['#00ff00', '#ffff00', '#ff0000', '#00ffff', '#ff00ff', '#0000ff']
            
            self.service_ax.pie(sizes, labels=labels, colors=colors[:len(labels)], autopct='%1.1f%%')
            self.service_ax.set_title('Service Distribution', color='white')
            self.service_fig.patch.set_facecolor('#1a1a1a')
            self.service_canvas.draw()
        
        # Update port status chart
        status_data = port_data.get('status_distribution', {})
        
        if status_data:
            self.status_ax.clear()
            statuses = list(status_data.keys())
            counts = list(status_data.values())
            colors = ['#00ff00' if s == 'open' else '#ff0000' for s in statuses]
            
            bars = self.status_ax.bar(statuses, counts, color=colors, edgecolor='white')
            self.status_ax.set_title('Port Status Distribution', color='white')
            self.status_ax.set_xlabel('Status', color='white')
            self.status_ax.set_ylabel('Count', color='white')
            self.status_ax.tick_params(colors='white')
            self.status_ax.set_facecolor('#1a1a1a')
            self.status_fig.patch.set_facecolor('#1a1a1a')
            
            # Add count labels
            for bar, count in zip(bars, counts):
                height = bar.get_height()
                self.status_ax.text(bar.get_x() + bar.get_width()/2., height,
                                   f'{count}', ha='center', va='bottom', color='white')
            
            self.status_canvas.draw()
    
    def update_threat_charts(self):
        """Update threat charts"""
        if not MATPLOTLIB_AVAILABLE:
            return
        
        # Get threat statistics
        threat_stats = self.db_manager.get_threat_stats(24)  # Last 24 hours
        
        # Update threat type chart
        if threat_stats:
            self.threat_type_ax.clear()
            threats = list(threat_stats.keys())
            counts = list(threat_stats.values())
            colors = ['#ff0000', '#ff6600', '#ffff00', '#00ff00', '#00ffff']
            
            bars = self.threat_type_ax.bar(threats, counts, color=colors[:len(threats)], edgecolor='white')
            self.threat_type_ax.set_title('Threat Type Distribution', color='white')
            self.threat_type_ax.set_xlabel('Threat Type', color='white')
            self.threat_type_ax.set_ylabel('Count', color='white')
            self.threat_type_ax.tick_params(colors='white')
            self.threat_type_ax.set_facecolor('#1a1a1a')
            self.threat_type_fig.patch.set_facecolor('#1a1a1a')
            
            # Add count labels
            for bar, count in zip(bars, counts):
                height = bar.get_height()
                self.threat_type_ax.text(bar.get_x() + bar.get_width()/2., height,
                                        f'{count}', ha='center', va='bottom', color='white')
            
            self.threat_type_canvas.draw()
        
        # Update severity chart (example data)
        severity_data = {'High': 5, 'Medium': 10, 'Low': 15}
        
        self.severity_ax.clear()
        severities = list(severity_data.keys())
        counts = list(severity_data.values())
        colors = ['#ff0000', '#ffff00', '#00ff00']
        
        self.severity_ax.pie(counts, labels=severities, colors=colors, autopct='%1.1f%%')
        self.severity_ax.set_title('Threat Severity Distribution', color='white')
        self.severity_fig.patch.set_facecolor('#1a1a1a')
        self.severity_canvas.draw()
    
    def update_system_charts(self):
        """Update system charts"""
        if not MATPLOTLIB_AVAILABLE:
            return
        
        # Update usage chart
        cpu = psutil.cpu_percent()
        memory = psutil.virtual_memory().percent
        
        self.usage_ax.clear()
        categories = ['CPU', 'Memory']
        values = [cpu, memory]
        colors = ['#00ff00', '#0000ff']
        
        bars = self.usage_ax.bar(categories, values, color=colors, edgecolor='white')
        self.usage_ax.set_title('System Resource Usage', color='white')
        self.usage_ax.set_ylabel('Percentage (%)', color='white')
        self.usage_ax.set_ylim(0, 100)
        self.usage_ax.tick_params(colors='white')
        self.usage_ax.set_facecolor('#1a1a1a')
        self.usage_fig.patch.set_facecolor('#1a1a1a')
        
        # Add percentage labels
        for bar, value in zip(bars, values):
            height = bar.get_height()
            self.usage_ax.text(bar.get_x() + bar.get_width()/2., height,
                              f'{value:.1f}%', ha='center', va='bottom', color='white')
        
        self.usage_canvas.draw()
        
        # Update connections chart (example data)
        try:
            connections = len(psutil.net_connections())
            self.conn_ax.clear()
            
            # Simulate connection types
            conn_types = ['ESTABLISHED', 'LISTEN', 'TIME_WAIT']
            conn_counts = [connections//2, connections//4, connections//4]
            
            self.conn_ax.pie(conn_counts, labels=conn_types, autopct='%1.1f%%')
            self.conn_ax.set_title('Network Connections', color='white')
            self.conn_fig.patch.set_facecolor('#1a1a1a')
            self.conn_canvas.draw()
        except:
            pass
    
    def refresh_charts(self):
        """Refresh all charts"""
        self.update_charts()
    
    def clear_chart_data(self):
        """Clear chart data"""
        # Clear database chart data
        self.db_manager.clear_old_data(0)  # Clear all data
        
        # Clear chart displays
        axes = [self.packet_ax, self.threat_ax, self.service_ax, self.status_ax,
                self.threat_type_ax, self.severity_ax, self.usage_ax, self.conn_ax]
        
        for ax in axes:
            if hasattr(ax, 'clear'):
                ax.clear()
        
        # Redraw canvases
        canvases = [self.packet_canvas, self.threat_canvas, self.service_canvas, self.status_canvas,
                   self.threat_type_canvas, self.severity_canvas, self.usage_canvas, self.conn_canvas]
        
        for canvas in canvases:
            if hasattr(canvas, 'draw'):
                canvas.draw()
    
    def export_charts(self):
        """Export charts to files"""
        directory = filedialog.askdirectory(title="Select directory to save charts")
        if not directory:
            return
        
        # Create charts directory
        charts_dir = os.path.join(directory, 'charts')
        os.makedirs(charts_dir, exist_ok=True)
        
        # Generate and save charts
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Get data for charts
        chart_data = self.monitor.get_chart_data()
        threat_stats = self.db_manager.get_threat_stats(24)
        
        # Create and save packet distribution chart
        if chart_data.get('protocol_history'):
            latest_protocol = chart_data['protocol_history'][-1] if chart_data['protocol_history'] else {'TCP': 0, 'UDP': 0, 'ICMP': 0}
            protocol_data = {k: v for k, v in latest_protocol.items() if v > 0}
            if protocol_data:
                fig = self.chart_manager.create_packet_distribution_chart(protocol_data, "Packet Distribution")
                if fig:
                    self.chart_manager.save_chart(fig, os.path.join(charts_dir, f'packet_dist_{timestamp}.png'))
        
        # Create and save threat distribution chart
        if threat_stats:
            fig = self.chart_manager.create_threat_distribution_chart(threat_stats, "Threat Distribution (24h)")
            if fig:
                self.chart_manager.save_chart(fig, os.path.join(charts_dir, f'threat_dist_{timestamp}.png'))
        
        # Create and save real-time chart
        if chart_data.get('timestamps'):
            fig = self.chart_manager.create_real_time_chart(chart_data, "Real-time Network Traffic")
            if fig:
                self.chart_manager.save_chart(fig, os.path.join(charts_dir, f'realtime_{timestamp}.png'))
        
        messagebox.showinfo("Success", f"Charts exported to {charts_dir}")
    
    def generate_report(self):
        """Generate comprehensive report"""
        # Get data for report
        threats = self.db_manager.get_recent_intrusions(100)
        threat_stats = self.db_manager.get_threat_stats(24)
        stats = self.monitor.get_current_stats()
        
        # Create report
        report = "=" * 60 + "\n"
        report += "ACCURATE CYBER DEFENSE SECURITY REPORT\n"
        report += "=" * 60 + "\n\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Tool Version: {VERSION}\n\n"
        
        report += "SYSTEM STATUS\n"
        report += "-" * 40 + "\n"
        report += f"Monitoring: {'Active' if stats['is_monitoring'] else 'Inactive'}\n"
        report += f"Target IP: {stats['target_ip'] or 'All traffic'}\n"
        report += f"Packets Processed: {stats['packets_processed']:,}\n"
        report += f"Threats Detected: {stats['threats_detected']:,}\n"
        report += f"Unique IPs: {stats['unique_ips']:,}\n\n"
        
        report += "THREAT STATISTICS (Last 24 hours)\n"
        report += "-" * 40 + "\n"
        if threat_stats:
            for threat_type, count in threat_stats.items():
                report += f"{threat_type}: {count}\n"
        else:
            report += "No threats detected\n"
        report += "\n"
        
        report += "RECENT THREATS\n"
        report += "-" * 40 + "\n"
        if threats:
            for timestamp, source_ip, threat_type, severity, description in threats[:20]:
                report += f"{timestamp} - {source_ip} - {threat_type} ({severity})\n"
                if description:
                    report += f"  {description}\n"
        else:
            report += "No recent threats\n"
        
        # Save report to file
        filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        os.makedirs(REPORT_DIR, exist_ok=True)
        filepath = os.path.join(REPORT_DIR, filename)
        
        with open(filepath, 'w') as f:
            f.write(report)
        
        # Show report in terminal
        self.terminal_output.config(state=tk.NORMAL)
        self.terminal_output.insert(tk.END, f"\nReport generated: {filename}\n")
        self.terminal_output.insert(tk.END, report + "\n")
        self.terminal_output.config(state=tk.DISABLED)
        self.terminal_output.see(tk.END)
        
        messagebox.showinfo("Report Generated", f"Report saved to {filename}")
    
    def new_session(self):
        """Create new session"""
        if self.monitor.is_monitoring:
            if not messagebox.askyesno("Confirm", "Stop current monitoring session?"):
                return
            self.stop_monitoring()
        
        self.monitor_ip_entry.delete(0, tk.END)
        self.scan_target_entry.delete(0, tk.END)
        self.clear_chart_data()
        self.log_message("New session created")
    
    def load_session(self):
        """Load saved session"""
        file_path = filedialog.askopenfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    session_data = json.load(f)
                
                self.monitor_ip_entry.delete(0, tk.END)
                self.monitor_ip_entry.insert(0, session_data.get('target_ip', ''))
                
                self.scan_target_entry.delete(0, tk.END)
                self.scan_target_entry.insert(0, session_data.get('scan_target', ''))
                
                self.log_message(f"Session loaded from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load session: {str(e)}")
    
    def save_session(self):
        """Save current session"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                session_data = {
                    'target_ip': self.monitor_ip_entry.get(),
                    'scan_target': self.scan_target_entry.get(),
                    'timestamp': datetime.now().isoformat()
                }
                
                with open(file_path, 'w') as f:
                    json.dump(session_data, f, indent=4)
                
                self.log_message(f"Session saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save session: {str(e)}")
    
    def configure_telegram(self):
        """Configure Telegram integration"""
        config_window = tk.Toplevel(self.root)
        config_window.title("Configure Telegram")
        config_window.geometry("500x300")
        
        ttk.Label(config_window, text="Telegram Configuration", font=('Arial', 12, 'bold')).pack(pady=10)
        
        # Token input
        token_frame = ttk.Frame(config_window)
        token_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(token_frame, text="Bot Token:").pack(side=tk.LEFT)
        token_entry = ttk.Entry(token_frame, width=40, show="*")
        token_entry.pack(side=tk.LEFT, padx=10)
        if self.telegram_manager.telegram_token:
            token_entry.insert(0, self.telegram_manager.telegram_token)
        
        # Chat ID input
        chat_frame = ttk.Frame(config_window)
        chat_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(chat_frame, text="Chat ID:").pack(side=tk.LEFT)
        chat_entry = ttk.Entry(chat_frame, width=20)
        chat_entry.pack(side=tk.LEFT, padx=10)
        if self.telegram_manager.telegram_chat_id:
            chat_entry.insert(0, self.telegram_manager.telegram_chat_id)
        
        # Status display
        status_text = scrolledtext.ScrolledText(config_window, height=5, wrap=tk.WORD)
        status_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        status_text.config(state=tk.DISABLED)
        
        def update_status(message):
            status_text.config(state=tk.NORMAL)
            status_text.delete(1.0, tk.END)
            status_text.insert(tk.END, message)
            status_text.config(state=tk.DISABLED)
        
        # Buttons
        button_frame = ttk.Frame(config_window)
        button_frame.pack(pady=10)
        
        def configure():
            token = token_entry.get().strip()
            chat_id = chat_entry.get().strip()
            
            if token:
                result = self.telegram_manager.config_telegram_token(token)
                update_status(result)
            
            if chat_id:
                result = self.telegram_manager.config_telegram_chat_id(chat_id)
                update_status(result)
        
        def test():
            result = self.telegram_manager.test_telegram_connection()
            update_status(result)
        
        ttk.Button(button_frame, text="Configure", command=configure).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Test Connection", command=test).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Close", command=config_window.destroy).pack(side=tk.LEFT, padx=5)
    
    def test_telegram_connection(self):
        """Test Telegram connection"""
        result = self.telegram_manager.test_telegram_connection()
        messagebox.showinfo("Telegram Test", result)
    
    def send_telegram_test(self):
        """Send test Telegram message"""
        test_message = f"🔒 Cyber Security Tool Test\nVersion: {VERSION}\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nStatus: Operational ✅"
        
        if self.telegram_manager.send_telegram_message(test_message):
            messagebox.showinfo("Success", "Test message sent successfully")
        else:
            messagebox.showerror("Error", "Failed to send test message")
    
    def export_to_telegram(self):
        """Export data to Telegram"""
        result = self.telegram_manager.export_data()
        messagebox.showinfo("Export Result", result)
    
    def open_traffic_generator(self):
        """Open traffic generator window"""
        traffic_window = tk.Toplevel(self.root)
        traffic_window.title("Traffic Generator")
        traffic_window.geometry("600x500")
        
        main_frame = ttk.Frame(traffic_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Target configuration
        ttk.Label(main_frame, text="Target IP:").grid(row=0, column=0, sticky=tk.W, pady=5)
        target_entry = ttk.Entry(main_frame, width=20)
        target_entry.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(main_frame, text="Port:").grid(row=1, column=0, sticky=tk.W, pady=5)
        port_entry = ttk.Entry(main_frame, width=10)
        port_entry.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        port_entry.insert(0, "80")
        
        # Traffic type
        ttk.Label(main_frame, text="Traffic Type:").grid(row=2, column=0, sticky=tk.W, pady=5)
        traffic_type = ttk.Combobox(main_frame, values=["TCP", "UDP", "ICMP", "Mixed"], width=10)
        traffic_type.grid(row=2, column=1, sticky=tk.W, pady=5, padx=5)
        traffic_type.current(0)
        
        # Packet configuration
        ttk.Label(main_frame, text="Packet Count:").grid(row=3, column=0, sticky=tk.W, pady=5)
        packet_count = ttk.Entry(main_frame, width=10)
        packet_count.grid(row=3, column=1, sticky=tk.W, pady=5, padx=5)
        packet_count.insert(0, "100")
        
        ttk.Label(main_frame, text="Delay (ms):").grid(row=4, column=0, sticky=tk.W, pady=5)
        delay_entry = ttk.Entry(main_frame, width=10)
        delay_entry.grid(row=4, column=1, sticky=tk.W, pady=5, padx=5)
        delay_entry.insert(0, "10")
        
        # Output console
        output_text = scrolledtext.ScrolledText(main_frame, width=70, height=10)
        output_text.grid(row=5, column=0, columnspan=2, pady=10)
        
        def log_output(message):
            output_text.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')} - {message}\n")
            output_text.see(tk.END)
        
        # Create traffic generator
        traffic_gen = NetworkTrafficGenerator(self.db_manager)
        
        def start_traffic():
            target = target_entry.get().strip()
            traffic_type_val = traffic_type.get()
            
            if not target:
                messagebox.showerror("Error", "Please enter a target IP")
                return
            
            try:
                packet_count_val = int(packet_count.get())
                delay_val = float(delay_entry.get()) / 1000
            except ValueError:
                messagebox.showerror("Error", "Invalid numeric values")
                return
            
            log_output(f"Starting {traffic_type_val} traffic to {target}...")
            
            def traffic_thread():
                try:
                    if traffic_type_val == "TCP":
                        port = int(port_entry.get())
                        result = traffic_gen.generate_tcp_traffic(target, port, packet_count_val, delay_val)
                    elif traffic_type_val == "UDP":
                        port = int(port_entry.get())
                        result = traffic_gen.generate_udp_traffic(target, port, packet_count_val, delay_val)
                    elif traffic_type_val == "ICMP":
                        result = traffic_gen.generate_icmp_traffic(target, packet_count_val, delay_val)
                    else:  # Mixed
                        # Generate mixed traffic
                        threads = []
                        port = int(port_entry.get())
                        
                        tcp_thread = threading.Thread(
                            target=lambda: traffic_gen.generate_tcp_traffic(target, port, packet_count_val//3, delay_val)
                        )
                        udp_thread = threading.Thread(
                            target=lambda: traffic_gen.generate_udp_traffic(target, port, packet_count_val//3, delay_val)
                        )
                        icmp_thread = threading.Thread(
                            target=lambda: traffic_gen.generate_icmp_traffic(target, packet_count_val//3, delay_val)
                        )
                        
                        threads = [tcp_thread, udp_thread, icmp_thread]
                        for thread in threads:
                            thread.start()
                        
                        for thread in threads:
                            thread.join()
                        
                        result = f"✅ Sent mixed traffic to {target}"
                    
                    log_output(result)
                    
                except Exception as e:
                    log_output(f"❌ Error: {str(e)}")
            
            thread = threading.Thread(target=traffic_thread, daemon=True)
            thread.start()
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Start Traffic", command=start_traffic).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Stop Traffic", command=traffic_gen.stop_traffic).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Close", command=traffic_window.destroy).pack(side=tk.LEFT, padx=5)
    
    def open_port_scanner(self):
        """Open port scanner"""
        self.chart_notebook.select(self.port_scan_chart_tab)
    
    def open_vulnerability_scanner(self):
        """Open vulnerability scanner"""
        target = self.scan_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target in the Scanner tab")
            return
        
        self.run_vuln_scan()
    
    def open_network_analyzer(self):
        """Open network analyzer"""
        analyzer_window = tk.Toplevel(self.root)
        analyzer_window.title("Network Analyzer")
        analyzer_window.geometry("800x600")
        
        # Create notebook for analyzer
        analyzer_notebook = ttk.Notebook(analyzer_window)
        analyzer_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Interface analyzer tab
        interface_tab = ttk.Frame(analyzer_notebook)
        analyzer_notebook.add(interface_tab, text="Interfaces")
        
        # Get interface information
        interfaces = self.get_network_interfaces()
        
        for i, iface in enumerate(interfaces):
            try:
                addrs = netifaces.ifaddresses(iface)
                frame = ttk.LabelFrame(interface_tab, text=f"Interface: {iface}")
                frame.pack(fill=tk.X, padx=10, pady=5)
                
                info_text = f"Interface: {iface}\n"
                
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        info_text += f"IPv4: {addr.get('addr', 'N/A')}\n"
                        info_text += f"Netmask: {addr.get('netmask', 'N/A')}\n"
                
                if netifaces.AF_INET6 in addrs:
                    for addr in addrs[netifaces.AF_INET6]:
                        info_text += f"IPv6: {addr.get('addr', 'N/A')}\n"
                
                ttk.Label(frame, text=info_text).pack(padx=5, pady=5)
            except:
                pass
        
        # Connection analyzer tab
        conn_tab = ttk.Frame(analyzer_notebook)
        analyzer_notebook.add(conn_tab, text="Connections")
        
        try:
            connections = psutil.net_connections()
            conn_text = scrolledtext.ScrolledText(conn_tab, wrap=tk.WORD)
            conn_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            conn_info = f"Total Connections: {len(connections)}\n\n"
            
            for conn in connections[:50]:  # Show first 50 connections
                conn_info += f"Family: {conn.family.name}\n"
                conn_info += f"Type: {conn.type.name}\n"
                if conn.laddr:
                    conn_info += f"Local: {conn.laddr}\n"
                if conn.raddr:
                    conn_info += f"Remote: {conn.raddr}\n"
                conn_info += f"Status: {conn.status}\n"
                conn_info += "-" * 40 + "\n"
            
            conn_text.insert(tk.END, conn_info)
            conn_text.config(state=tk.DISABLED)
        except:
            ttk.Label(conn_tab, text="Unable to retrieve connections").pack(pady=20)
    
    def show_user_guide(self):
        """Show user guide"""
        guide = """
Advanced Cyber Security Tool User Guide

1. MONITORING:
   - Enter target IP (optional) and select interface
   - Click "Start Monitoring" to begin
   - Real-time charts will show network activity
   - Click "Stop Monitoring" to stop

2. NETWORK TOOLS:
   - Ping: Test connectivity to IP
   - Port Scan: Scan for open ports
   - Deep Scan: Comprehensive port scan
   - Traceroute: Trace network path
   - Vuln Scan: Check for vulnerabilities
   - Get Location: Geolocate IP address
   - Analyze IP: Comprehensive analysis

3. CHARTS:
   - Real-time Charts: Live network traffic
   - Port Scan Charts: Visualize scan results
   - Threat Charts: Threat distribution
   - System Charts: Resource usage

4. TELEGRAM:
   - Configure bot token and chat ID
   - Send alerts and reports
   - Remote control via commands

5. EXPORT:
   - Export charts as images
   - Generate security reports
   - Save sessions for later

Keyboard Shortcuts:
  Ctrl+S: Save session
  Ctrl+L: Load session
  Ctrl+E: Export charts
  Ctrl+R: Generate report
  Ctrl+Q: Quit
        """
        
        guide_window = tk.Toplevel(self.root)
        guide_window.title("User Guide")
        guide_window.geometry("700x500")
        
        guide_text = scrolledtext.ScrolledText(guide_window, wrap=tk.WORD)
        guide_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        guide_text.insert(tk.END, guide)
        guide_text.config(state=tk.DISABLED)
    
    def show_about(self):
        """Show about information"""
        about = f"""
Accurate Cyber Defense Tool v{VERSION}

A comprehensive network security monitoring and analysis tool.

Features:
- Real-time network monitoring
- Advanced threat detection
- Port and vulnerability scanning
- Traffic generation for testing
- Telegram integration
- Real-time charts and visualization
- Database logging and reporting

Author: Ian Carter Kulani
Email: iancarterkulani@gmail.com
Phone: +265(0)988061969

Community: https://github.com/Accurate-Cyber-Defense

This tool is for educational and authorized security testing only.
Use responsibly and only on networks you own or have permission to test.
        """
        
        messagebox.showinfo("About", about)
    
    def log_message(self, message: str):
        """Log message to terminal"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.terminal_output.config(state=tk.NORMAL)
        self.terminal_output.insert(tk.END, f"[{timestamp}] {message}\n")
        self.terminal_output.config(state=tk.DISABLED)
        self.terminal_output.see(tk.END)
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

class TerminalEmulator:
    """Enhanced terminal emulator for CLI mode"""
    
    def __init__(self, network_scanner: NetworkScanner, network_monitor: NetworkMonitor, 
                 traffic_generator: NetworkTrafficGenerator, telegram_manager: TelegramManager):
        self.scanner = network_scanner
        self.monitor = network_monitor
        self.traffic_generator = traffic_generator
        self.telegram_manager = telegram_manager
        self.db_manager = network_scanner.db_manager
        
        self.commands = {
            'help': self.cmd_help,
            'ping': self.cmd_ping,
            'scan': self.cmd_scan,
            'deepscan': self.cmd_deep_scan,
            'traceroute': self.cmd_traceroute,
            'tracert': self.cmd_traceroute,
            'vulnscan': self.cmd_vulnscan,
            'location': self.cmd_location,
            'analyze': self.cmd_analyze,
            'start': self.cmd_start,
            'stop': self.cmd_stop,
            'status': self.cmd_status,
            'threats': self.cmd_threats,
            'netstat': self.cmd_netstat,
            'ifconfig': self.cmd_ifconfig,
            'whois': self.cmd_whois,
            'dns': self.cmd_dns,
            'traffic': self.cmd_traffic,
            'telegram': self.cmd_telegram,
            'report': self.cmd_report,
            'clear': self.cmd_clear,
            'exit': self.cmd_exit,
            'quit': self.cmd_exit
        }
    
    def execute(self, command: str) -> str:
        """Execute terminal command"""
        parts = command.strip().split()
        if not parts:
            return ""
        
        cmd = parts[0].lower()
        args = parts[1:]
        
        if cmd in self.commands:
            try:
                return self.commands[cmd](args)
            except Exception as e:
                return f"❌ Error executing command: {str(e)}"
        else:
            return f"❌ Command not found: {cmd}\nType 'help' for available commands"
    
    def cmd_help(self, args):
        """Show help"""
        help_text = f"""
{Colors.GREEN}{Colors.BOLD}ACCURATE CYBER DEFENSE v{VERSION} - COMMAND REFERENCE{Colors.END}

{Colors.CYAN}Network Diagnostics:{Colors.END}
  {Colors.GREEN}ping IP{Colors.END}              - Ping an IP address
  {Colors.GREEN}scan IP{Colors.END}             - Quick port scan
  {Colors.GREEN}deepscan IP{Colors.END}         - Comprehensive port scan
  {Colors.GREEN}traceroute TARGET{Colors.END}   - Trace route to target
  {Colors.GREEN}vulnscan TARGET{Colors.END}     - Vulnerability scan
  {Colors.GREEN}location IP{Colors.END}         - Get IP geolocation
  {Colors.GREEN}analyze IP{Colors.END}          - Deep analysis of IP

{Colors.CYAN}Monitoring:{Colors.END}
  {Colors.GREEN}start [IP]{Colors.END}          - Start monitoring (optional IP)
  {Colors.GREEN}stop{Colors.END}                - Stop monitoring
  {Colors.GREEN}status{Colors.END}              - Show system status
  {Colors.GREEN}threats{Colors.END}             - Show recent threats

{Colors.CYAN}System Tools:{Colors.END}
  {Colors.GREEN}netstat{Colors.END}             - Show network connections
  {Colors.GREEN}ifconfig{Colors.END}            - Network interface info
  {Colors.GREEN}whois DOMAIN{Colors.END}        - WHOIS lookup
  {Colors.GREEN}dns DOMAIN{Colors.END}          - DNS resolution

{Colors.CYAN}Traffic Generation:{Colors.END}
  {Colors.GREEN}traffic IP [PORT] [COUNT]{Colors.END} - Generate test traffic

{Colors.CYAN}Telegram:{Colors.END}
  {Colors.GREEN}telegram status{Colors.END}     - Show Telegram status
  {Colors.GREEN}telegram test{Colors.END}       - Test Telegram connection
  {Colors.GREEN}telegram send MESSAGE{Colors.END} - Send Telegram message

{Colors.CYAN}Reporting:{Colors.END}
  {Colors.GREEN}report{Colors.END}              - Generate security report

{Colors.CYAN}System:{Colors.END}
  {Colors.GREEN}clear{Colors.END}               - Clear screen
  {Colors.GREEN}exit{Colors.END}               - Exit program
  {Colors.GREEN}quit{Colors.END}               - Exit program

{Colors.YELLOW}Examples:{Colors.END}
  ping 8.8.8.8
  scan 192.168.1.1
  traceroute google.com
  location 1.1.1.1
  start 192.168.1.1
  status
  threats
        """
        return help_text
    
    def cmd_ping(self, args):
        """Ping command"""
        if not args:
            return "Usage: ping <IP>"
        return self.scanner.ping_ip(args[0])
    
    def cmd_scan(self, args):
        """Port scan command"""
        if not args:
            return "Usage: scan <IP>"
        
        result = self.scanner.scan_ip(args[0])
        if result['success']:
            response = f"🔍 Scan Results for {args[0]}:\n"
            response += f"Open Ports: {len(result.get('open_ports', []))}\n\n"
            for port in result.get('open_ports', [])[:10]:
                response += f"  Port {port}: {result['services'].get(port, 'Unknown')}\n"
            return response
        else:
            return f"❌ Scan error: {result.get('error', 'Unknown')}"
    
    def cmd_deep_scan(self, args):
        """Deep scan command"""
        if not args:
            return "Usage: deepscan <IP>"
        
        result = self.scanner.deep_scan_ip(args[0])
        if result['success']:
            response = f"🔍 Deep Scan Results for {args[0]}:\n"
            response += f"State: {result.get('state', 'Unknown')}\n"
            response += f"Open Ports: {len(result.get('open_ports', []))}\n\n"
            for port in result.get('open_ports', [])[:5]:
                service_info = result['services'].get(port, {})
                response += f"  Port {port}: {service_info.get('name', 'unknown')}\n"
            return response
        else:
            return f"❌ Deep scan error: {result.get('error', 'Unknown')}"
    
    def cmd_traceroute(self, args):
        """Traceroute command"""
        if not args:
            return "Usage: traceroute <TARGET>"
        return self.scanner.traceroute(args[0])
    
    def cmd_vulnscan(self, args):
        """Vulnerability scan command"""
        if not args:
            return "Usage: vulnscan <TARGET>"
        
        result = self.scanner.vulnerability_scan(args[0])
        if result['success']:
            response = f"🔍 Vulnerability Scan for {args[0]}:\n"
            response += f"Vulnerabilities found: {len(result.get('vulnerabilities', []))}\n"
            return response
        else:
            return f"❌ Vuln scan error: {result.get('error', 'Unknown')}"
    
    def cmd_location(self, args):
        """Location command"""
        if not args:
            return "Usage: location <IP>"
        return self.scanner.get_ip_location(args[0])
    
    def cmd_analyze(self, args):
        """Analyze command"""
        if not args:
            return "Usage: analyze <IP>"
        
        ip = args[0]
        response = f"🔍 Analysis for {ip}:\n\n"
        
        # Ping
        response += "1. Ping Test:\n"
        response += self.scanner.ping_ip(ip) + "\n\n"
        
        # Quick Scan
        response += "2. Quick Port Scan:\n"
        result = self.scanner.scan_ip(ip)
        if result['success']:
            response += f"   Open ports: {len(result.get('open_ports', []))}\n"
        else:
            response += "   Scan failed\n"
        
        # Location
        response += "\n3. Location Information:\n"
        response += self.scanner.get_ip_location(ip)
        
        return response
    
    def cmd_start(self, args):
        """Start monitoring command"""
        target_ip = args[0] if args else None
        if self.monitor.start_monitoring(target_ip):
            return f"✅ Started monitoring {target_ip if target_ip else 'all traffic'}"
        else:
            return "⚠ Monitoring is already active"
    
    def cmd_stop(self, args):
        """Stop monitoring command"""
        self.monitor.stop_monitoring()
        return "✅ Stopped monitoring"
    
    def cmd_status(self, args):
        """Status command"""
        stats = self.monitor.get_current_stats()
        
        response = f"{Colors.CYAN}System Status:{Colors.END}\n"
        response += f"  Monitoring: {'✅ Active' if stats['is_monitoring'] else '❌ Inactive'}\n"
        response += f"  Target: {stats['target_ip'] or 'All traffic'}\n"
        response += f"  Packets: {stats['packets_processed']:,}\n"
        response += f"  Threats: {stats['threats_detected']:,}\n"
        response += f"  Unique IPs: {stats['unique_ips']:,}\n"
        response += f"  Packet Rate: {stats['packet_rate']:.2f}/s\n"
        
        # System info
        cpu = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        
        response += f"\n{Colors.CYAN}System Resources:{Colors.END}\n"
        response += f"  CPU: {cpu}%\n"
        response += f"  Memory: {memory.percent}%\n"
        
        return response
    
    def cmd_threats(self, args):
        """Threats command"""
        threats = self.db_manager.get_recent_intrusions(10)
        
        if not threats:
            return "✅ No threats detected"
        
        response = f"{Colors.RED}Recent Threats:{Colors.END}\n"
        for timestamp, source_ip, threat_type, severity, description in threats:
            color = Colors.RED if severity.lower() == 'high' else Colors.YELLOW if severity.lower() == 'medium' else Colors.GREEN
            response += f"{color}[{severity}] {timestamp} - {source_ip} - {threat_type}{Colors.END}\n"
            if description:
                response += f"  {description[:50]}...\n"
        
        return response
    
    def cmd_netstat(self, args):
        """Netstat command"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
            else:
                result = subprocess.run(['netstat', '-tulpn'], capture_output=True, text=True)
            
            output = result.stdout[:1000] + "..." if len(result.stdout) > 1000 else result.stdout
            return output
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    def cmd_ifconfig(self, args):
        """Ifconfig command"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
            else:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
            
            output = result.stdout[:1000] + "..." if len(result.stdout) > 1000 else result.stdout
            return output
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    def cmd_whois(self, args):
        """Whois command"""
        if not args:
            return "Usage: whois <DOMAIN>"
        
        try:
            result = subprocess.run(['whois', args[0]], capture_output=True, text=True, timeout=30)
            output = result.stdout[:500] + "..." if len(result.stdout) > 500 else result.stdout
            return output
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    def cmd_dns(self, args):
        """DNS command"""
        if not args:
            return "Usage: dns <DOMAIN>"
        
        try:
            ip = socket.gethostbyname(args[0])
            return f"{args[0]} → {ip}"
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    def cmd_traffic(self, args):
        """Traffic generation command"""
        if len(args) < 1:
            return "Usage: traffic <IP> [PORT=80] [COUNT=100]"
        
        ip = args[0]
        port = int(args[1]) if len(args) > 1 else 80
        count = int(args[2]) if len(args) > 2 else 100
        
        return self.traffic_generator.generate_tcp_traffic(ip, port, count, 0.01)
    
    def cmd_telegram(self, args):
        """Telegram command"""
        if not args:
            return "Usage: telegram <status|test|send MESSAGE>"
        
        subcmd = args[0].lower()
        
        if subcmd == 'status':
            return self.telegram_manager.get_telegram_status()
        elif subcmd == 'test':
            return self.telegram_manager.test_telegram_connection()
        elif subcmd == 'send' and len(args) > 1:
            message = ' '.join(args[1:])
            if self.telegram_manager.send_telegram_message(message):
                return "✅ Message sent successfully"
            else:
                return "❌ Failed to send message"
        else:
            return "❌ Unknown telegram command"
    
    def cmd_report(self, args):
        """Report command"""
        threats = self.db_manager.get_recent_intrusions(50)
        threat_stats = self.db_manager.get_threat_stats(24)
        stats = self.monitor.get_current_stats()
        
        report = "=" * 60 + "\n"
        report += "SECURITY REPORT\n"
        report += "=" * 60 + "\n\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Tool Version: {VERSION}\n\n"
        
        report += "SYSTEM STATUS\n"
        report += "-" * 40 + "\n"
        report += f"Monitoring: {'Active' if stats['is_monitoring'] else 'Inactive'}\n"
        report += f"Packets Processed: {stats['packets_processed']:,}\n"
        report += f"Threats Detected: {stats['threats_detected']:,}\n\n"
        
        report += "THREAT STATISTICS (24h)\n"
        report += "-" * 40 + "\n"
        if threat_stats:
            for threat_type, count in threat_stats.items():
                report += f"{threat_type}: {count}\n"
        else:
            report += "No threats detected\n"
        report += "\n"
        
        report += "RECENT THREATS\n"
        report += "-" * 40 + "\n"
        if threats:
            for timestamp, source_ip, threat_type, severity, _ in threats[:10]:
                report += f"{timestamp} - {source_ip} - {threat_type} ({severity})\n"
        else:
            report += "No recent threats\n"
        
        return report
    
    def cmd_clear(self, args):
        """Clear command"""
        os.system('cls' if os.name == 'nt' else 'clear')
        return ""
    
    def cmd_exit(self, args):
        """Exit command"""
        return "EXIT"

def print_banner():
    """Print enhanced banner"""
    banner = f"""
{Colors.GREEN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                   ║
║  ACCURATE CYBER DEFENSE END POINT DETECTION  TOOL v{VERSION} 🛡️                  ║
║                                                                                  ║
║      Advanced Network Monitoring • Real-time Threat Detection • Charts           ║
║         Vulnerability Scanning • Traffic Generation • Telegram Integration       ║
║                    Dark/Light Themes • Database Logging • Reporting              ║
║                                                                                  ║
║ Author: Ian Carter Kulani Community: https://github.com/Accurate-Cyber-Defense   ║
║   Email: iancarterkulani@gmail.com      Phone: +265(0)988061969                  ║
║                                                                                  ║
║   Features:                                                                      ║
║   • Real-time Network Monitoring      • Advanced Threat Detection                ║
║   • Port & Vulnerability Scanning     • Traffic Generation Tools                 ║
║   • Intrusion Detection System        • Comprehensive Reporting                  ║
║   • CLI & GUI Interfaces              • Telegram Integration                     ║
║   • Real-time Charts & Graphs        • Dark/Light/Cyber Themes                   ║
║   • Database Logging & Analytics      • Network Traffic Analysis                 ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
{Colors.END}
"""
    print(banner)

def setup_directories():
    """Setup required directories"""
    directories = [REPORT_DIR, LOG_DIR]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)

def setup_logging():
    """Setup logging configuration"""
    log_file = os.path.join(LOG_DIR, 'cyber_tool.log')
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def cli_mode():
    """Run in CLI mode"""
    # Initialize components
    db_manager = DatabaseManager()
    network_scanner = NetworkScanner(db_manager)
    network_monitor = NetworkMonitor(db_manager)
    traffic_generator = NetworkTrafficGenerator(db_manager)
    telegram_manager = TelegramManager(db_manager)
    
    terminal = TerminalEmulator(network_scanner, network_monitor, traffic_generator, telegram_manager)
    
    print_banner()
    print(f"\n{Colors.GREEN}🔧 CLI Mode Activated{Colors.END}")
    print("Type 'help' for available commands")
    print("Type 'gui' to switch to GUI mode")
    print("Type 'exit' to quit\n")
    
    # Start Telegram update thread
    def telegram_update_thread():
        while True:
            try:
                telegram_manager.process_telegram_updates()
                time.sleep(2)
            except Exception as e:
                print(f"Telegram error: {e}")
                time.sleep(10)
    
    telegram_thread = threading.Thread(target=telegram_update_thread, daemon=True)
    telegram_thread.start()
    
    while True:
        try:
            command = input(f"{Colors.GREEN}cyberdefense>{Colors.END} ").strip()
            if not command:
                continue
            
            # Log command
            db_manager.log_command(command, 'cli', True)
            
            if command.lower() == 'exit' or command.lower() == 'quit':
                print(f"{Colors.YELLOW}👋 Exiting...{Colors.END}")
                network_monitor.stop_monitoring()
                traffic_generator.stop_traffic()
                break
            
            elif command.lower() == 'gui':
                print(f"{Colors.CYAN}🚀 Switching to GUI mode...{Colors.END}")
                return 'gui'
            
            else:
                result = terminal.execute(command)
                if result == "EXIT":
                    print(f"{Colors.YELLOW}👋 Exiting...{Colors.END}")
                    network_monitor.stop_monitoring()
                    traffic_generator.stop_traffic()
                    break
                elif result:
                    print(result)
        
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}👋 Exiting...{Colors.END}")
            network_monitor.stop_monitoring()
            traffic_generator.stop_traffic()
            break
        except Exception as e:
            print(f"{Colors.RED}❌ Error: {e}{Colors.END}")

def gui_mode():
    """Run in GUI mode"""
    if not GUI_AVAILABLE:
        print(f"{Colors.RED}❌ GUI mode requires tkinter. Please install it or use CLI mode.{Colors.END}")
        print("On Ubuntu/Debian: sudo apt-get install python3-tk")
        print("On Fedora/RHEL: sudo dnf install python3-tkinter")
        print("On macOS: brew install python-tk")
        print("On Windows: Usually included with Python")
        return 'cli'
    
    if not MATPLOTLIB_AVAILABLE:
        print(f"{Colors.YELLOW}⚠️  Chart features require matplotlib. Some features will be limited.{Colors.END}")
        print("Install: pip install matplotlib")
    
    # Initialize components
    db_manager = DatabaseManager()
    network_monitor = NetworkMonitor(db_manager)
    network_scanner = NetworkScanner(db_manager)
    telegram_manager = TelegramManager(db_manager)
    
    # Create main window
    root = tk.Tk()
    
    try:
        app = CyberSecurityDashboard(root, db_manager, network_monitor, network_scanner, telegram_manager)
        
        # Handle window close
        def on_closing():
            network_monitor.stop_monitoring()
            root.quit()
            root.destroy()
        
        root.protocol("WM_DELETE_WINDOW", on_closing)
        
        # Start Telegram update thread
        def telegram_update_thread():
            while True:
                try:
                    telegram_manager.process_telegram_updates()
                    time.sleep(2)
                except Exception as e:
                    print(f"Telegram error: {e}")
                    time.sleep(10)
        
        telegram_thread = threading.Thread(target=telegram_update_thread, daemon=True)
        telegram_thread.start()
        
        root.mainloop()
        
        return 'menu'
        
    except Exception as e:
        messagebox.showerror("Error", f"Failed to start GUI: {str(e)}")
        print(f"{Colors.RED}GUI Error: {e}{Colors.END}")
        return 'cli'

def main():
    """Main entry point"""
    # Setup
    setup_directories()
    setup_logging()
    
    print_banner()
    
    # Check for command line arguments
    parser = argparse.ArgumentParser(description='Accurate Cyber Defense Tool')
    parser.add_argument('--cli', action='store_true', help='Run in CLI mode')
    parser.add_argument('--gui', action='store_true', help='Run in GUI mode')
    
    args = parser.parse_args()
    
    if args.cli:
        mode = 'cli'
    elif args.gui:
        mode = 'gui'
    else:
        # Interactive mode selection
        print(f"\n{Colors.CYAN}Select mode:{Colors.END}")
        print("  1. CLI Mode (Command Line Interface)")
        print("  2. GUI Mode (Graphical User Interface)")
        print("  3. Exit")
        
        while True:
            try:
                choice = input(f"\n{Colors.GREEN}Select mode (1-3):{Colors.END} ").strip()
                if choice == '1':
                    mode = 'cli'
                    break
                elif choice == '2':
                    mode = 'gui'
                    break
                elif choice == '3':
                    print(f"{Colors.YELLOW}👋 Thank you for using Accurate Cyber Defense!{Colors.END}")
                    return
                else:
                    print(f"{Colors.RED}Invalid choice. Please enter 1, 2, or 3.{Colors.END}")
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}👋 Exiting...{Colors.END}")
                return
    
    # Run selected mode
    while True:
        if mode == 'cli':
            mode = cli_mode()
        elif mode == 'gui':
            mode = gui_mode()
        elif mode == 'menu':
            print(f"\n{Colors.CYAN}Select mode:{Colors.END}")
            print("  1. CLI Mode (Command Line Interface)")
            print("  2. GUI Mode (Graphical User Interface)")
            print("  3. Exit")
            
            try:
                choice = input(f"\n{Colors.GREEN}Select mode (1-3):{Colors.END} ").strip()
                if choice == '1':
                    mode = 'cli'
                elif choice == '2':
                    mode = 'gui'
                elif choice == '3':
                    print(f"{Colors.YELLOW}👋 Thank you for using Accurate Cyber Defense!{Colors.END}")
                    break
                else:
                    print(f"{Colors.RED}Invalid choice. Please enter 1, 2, or 3.{Colors.END}")
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}👋 Exiting...{Colors.END}")
                break
        else:
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}👋 Thank you for using Accurate Cyber Defense!{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}❌ Application error: {e}{Colors.END}")
        logging.exception("Application crash")