#!/usr/bin/env python3

import ipaddress
import random
import socket
import logging
import time
from typing import List, Tuple, Optional

logger = logging.getLogger("NetSecTest.Utils")

def random_ip() -> str:
    """Generate a random IP address."""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def generate_random_ips(count: int = 10) -> List[str]:
    """Generate a list of random IP addresses."""
    return [random_ip() for _ in range(count)]

def generate_random_ips_from_cidr(cidr: str, count: int = 10) -> List[str]:
    """Generate random IP addresses from a CIDR range."""
    try:
        network = ipaddress.ip_network(cidr)
        ips = []
        
        for _ in range(count):
            # Get a random IP in the network
            ip_int = random.randint(
                int(network.network_address), 
                int(network.broadcast_address)
            )
            ip = str(ipaddress.ip_address(ip_int))
            ips.append(ip)
        
        return ips
    except Exception as e:
        logger.error(f"Error generating IPs from CIDR {cidr}: {e}")
        return []

def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a specific port is open on an IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False

def scan_common_ports(ip: str, ports: List[int] = None, timeout: float = 0.5) -> List[int]:
    """Scan an IP for common open ports."""
    if ports is None:
        # Common ports to scan
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 
                 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    
    open_ports = []
    
    for port in ports:
        if is_port_open(ip, port, timeout):
            open_ports.append(port)
    
    return open_ports

def get_local_ip() -> str:
    """Get the local IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def check_connectivity() -> bool:
    """Check if there's internet connectivity."""
    try:
        # Try to connect to a reliable host
        socket.create_connection(("8.8.8.8", 53), timeout=1)
        return True
    except OSError:
        return False

def resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve a hostname to an IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.error:
        return None

def is_valid_ipv4(ip: str) -> bool:
    """Check if a string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False

def is_valid_cidr(cidr: str) -> bool:
    """Check if a string is a valid CIDR notation."""
    try:
        ipaddress.ip_network(cidr)
        return True
    except ValueError:
        return False

def format_time_duration(seconds: float) -> str:
    """Format a time duration in seconds to a human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} hours"

def current_timestamp() -> float:
    """Get current Unix timestamp."""
    return time.time()

def format_timestamp(timestamp: float) -> str:
    """Format a Unix timestamp to a human-readable date/time."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
