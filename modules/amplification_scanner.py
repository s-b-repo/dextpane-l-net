#!/usr/bin/env python3

import concurrent.futures
import ipaddress
import logging
import random
import socket
import struct
import threading
import time
from typing import Dict, List, Set, Tuple, Optional, Any

# Import necessary packages for specific protocols
from dns import resolver, message, rdatatype
from impacket.ImpactPacket import IP, UDP, Data

logger = logging.getLogger("NetSecTest.AmplificationScanner")

class AmplificationScanner:
    """Scanner for discovering and testing amplification servers."""
    
    def __init__(self, storage):
        """Initialize the amplification scanner."""
        self.storage = storage
        self.scanning = False
        self.scan_thread = None
        self.max_threads = 100  # Default thread count
        self.active_threads = 0
        self.thread_lock = threading.Lock()
        
        # Amplification protocols with their default ports
        self.protocols = {
            "DNS": 53,
            "NTP": 123,
            "CLDAP": 389,
            "MEMCACHED": 11211,
            "CHARGEN": 19,
            "SSDP": 1900,
            "QUIC": 443,
            "TFTP": 69,
            "PORTMAP": 111,
            "QOTD": 17,
            "SNMP": 161,
            "NETBIOS": 137,
            "MDNS": 5353,
            "ARD": 3283,     # Apple Remote Desktop
            "COAP": 5683,    # Constrained Application Protocol
            "RIP": 520,      # Routing Information Protocol
            "STEAM": 27015,  # Steam Protocol
            "FIVEM": 30120,  # FiveM GTA Protocol
            "WSD": 3702,     # Web Services Discovery
            "UBNT": 10001    # Ubiquiti Discovery Protocol
        }
        
        # Networks to scan for amplification servers
        self.networks_to_scan = [
            "8.0.0.0/8",       # Level3
            "9.0.0.0/8",       # IBM
            "11.0.0.0/8",      # DoD
            "28.0.0.0/8",      # DoD
            "29.0.0.0/8",      # DoD
            "30.0.0.0/8",      # DoD
            "33.0.0.0/8",      # HP
            "45.0.0.0/8",      # Various
            "46.0.0.0/8",      # Various
            "49.0.0.0/8",      # Various Asia
            "51.0.0.0/8",      # UK
            "52.0.0.0/8",      # Various
            "57.0.0.0/8",      # Various
            "62.0.0.0/8",      # RIPE NCC
            "63.0.0.0/8",      # ARIN
            "64.0.0.0/8",      # ARIN
            "65.0.0.0/8",      # ARIN
            "66.0.0.0/8",      # ARIN
            "67.0.0.0/8",      # ARIN
            "68.0.0.0/8",      # ARIN
            "80.0.0.0/8",      # RIPE NCC
            "81.0.0.0/8",      # RIPE NCC
            "82.0.0.0/8",      # RIPE NCC
            "83.0.0.0/8",      # RIPE NCC
            "84.0.0.0/8",      # RIPE NCC
            "85.0.0.0/8",      # RIPE NCC
            "86.0.0.0/8",      # RIPE NCC
            "87.0.0.0/8",      # RIPE NCC
            "88.0.0.0/8",      # RIPE NCC
            "89.0.0.0/8",      # RIPE NCC
            "95.0.0.0/8",      # RIPE NCC
            "113.0.0.0/8",     # APNIC
            "114.0.0.0/8",     # APNIC
            "115.0.0.0/8",     # APNIC
            "117.0.0.0/8",     # APNIC
            "118.0.0.0/8",     # APNIC
            "119.0.0.0/8",     # APNIC
            "125.0.0.0/8",     # APNIC
            "175.0.0.0/8",     # APNIC
            "180.0.0.0/8",     # APNIC
            "182.0.0.0/8",     # APNIC
            "183.0.0.0/8",     # APNIC
            "202.0.0.0/8",     # APNIC
            "203.0.0.0/8",     # APNIC
            "210.0.0.0/8",     # APNIC
            "211.0.0.0/8",     # APNIC
            "218.0.0.0/8",     # APNIC
            "219.0.0.0/8",     # APNIC
            "220.0.0.0/8",     # APNIC
            "221.0.0.0/8",     # APNIC
            "222.0.0.0/8",     # APNIC
            "223.0.0.0/8"      # APNIC
        ]
        
        # Initialize scanned IPs set
        self.scanned_ips = set()
        
        # Local IP to use for testing
        self.local_ip = self._get_local_ip()
    
    def _get_local_ip(self) -> str:
        """Get the local IP address."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
    
    def start_scanning(self) -> None:
        """Start the continuous amplification server scanning process."""
        if self.scanning:
            logger.warning("Amplification scanning already running")
            return
        
        self.scanning = True
        self.scan_thread = threading.Thread(target=self._scanning_thread, daemon=True)
        self.scan_thread.start()
        logger.info("Amplification server scanning started")
    
    def stop_scanning(self) -> None:
        """Stop the continuous amplification server scanning process."""
        if not self.scanning:
            logger.warning("Amplification scanning not running")
            return
        
        self.scanning = False
        if self.scan_thread:
            # Allow the thread to finish naturally
            self.scan_thread.join(timeout=2)
            self.scan_thread = None
        logger.info("Amplification scanning stopped")
    
    def get_thread_count(self) -> int:
        """Get the current number of active scanning threads."""
        return self.active_threads
    
    def set_max_threads(self, count: int) -> None:
        """Set the maximum number of concurrent scanning threads."""
        self.max_threads = max(1, min(500, count))  # Limit between 1 and 500
    
    def _scanning_thread(self) -> None:
        """Main scanning thread that runs continuously while scanning is enabled."""
        while self.scanning:
            try:
                # Randomly choose which protocol to scan for
                protocol = random.choice(list(self.protocols.keys()))
                port = self.protocols[protocol]
                
                # Scan random IPs for the selected protocol
                self._scan_random_ips(protocol, port, 50)  # Scan 50 random IPs
                
                # Periodically test existing amplification servers
                if random.random() < 0.2:  # 20% chance
                    self.test_all_servers()
                
                # Sleep between scan batches
                time.sleep(10)
            except Exception as e:
                logger.error(f"Error in scanning thread: {e}")
                time.sleep(30)  # Longer sleep on error
    
    def _scan_random_ips(self, protocol: str, port: int, count: int) -> None:
        """Scan random IPs for the specified amplification protocol."""
        targets = []
        
        # Generate random IPs from the networks list
        for _ in range(count):
            # Pick a random network
            network_str = random.choice(self.networks_to_scan)
            network = ipaddress.ip_network(network_str)
            
            # Get a random IP from the network
            ip_int = random.randint(
                int(network.network_address), 
                int(network.broadcast_address)
            )
            ip = str(ipaddress.ip_address(ip_int))
            
            # Skip already scanned IPs for this protocol
            key = f"{ip}:{protocol}"
            if key in self.scanned_ips:
                continue
            
            self.scanned_ips.add(key)
            targets.append(ip)
        
        # Scan the targets
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            
            for ip in targets:
                # Limit active threads
                with self.thread_lock:
                    self.active_threads += 1
                
                future = executor.submit(self._check_amplification, ip, protocol, port)
                future.add_done_callback(self._thread_completed_callback)
                futures.append(future)
            
            # Wait for all futures to complete
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self._save_amplification_server(result)
                except Exception as e:
                    logger.debug(f"Error checking amplification server: {e}")
    
    def _thread_completed_callback(self, future):
        """Callback when a thread is completed to decrement active thread count."""
        with self.thread_lock:
            self.active_threads -= 1
    
    def _check_amplification(self, ip: str, protocol: str, port: int) -> Optional[Dict[str, Any]]:
        """Check if the given IP is an amplification server for the specified protocol."""
        # Choose the appropriate test method based on protocol
        test_method = getattr(self, f"_test_{protocol.lower()}", None)
        if not test_method:
            logger.warning(f"No test method available for protocol {protocol}")
            return None
        
        try:
            # Test the server
            amplification_factor = test_method(ip, port)
            
            if amplification_factor > 1:
                logger.info(f"Found {protocol} amplification server at {ip}:{port} with factor {amplification_factor}")
                
                return {
                    "ip": ip,
                    "port": port,
                    "protocol": protocol,
                    "amplification_factor": amplification_factor,
                    "country": self._get_country(ip),
                    "working": True,
                    "last_checked": time.time()
                }
        except Exception as e:
            logger.debug(f"Error checking {protocol} amplification at {ip}:{port}: {e}")
        
        return None
    
    def _get_country(self, ip: str) -> str:
        """Try to determine the country of an IP address."""
        # In a real implementation, this would use a geolocation API or database
        # For simplicity, we'll just return "Unknown"
        return "Unknown"
    
    def _save_amplification_server(self, server_data: Dict[str, Any]) -> None:
        """Save a discovered amplification server to storage."""
        # Check if this server already exists
        existing = self.storage.find_amplification_server(
            server_data["ip"], 
            server_data["protocol"]
        )
        
        if existing:
            # Update the existing server
            existing.update({
                "working": server_data["working"],
                "amplification_factor": server_data["amplification_factor"],
                "last_checked": server_data["last_checked"]
            })
            self.storage.update_amplification_server(existing)
        else:
            # Add the new server
            self.storage.add_amplification_server(server_data)
            logger.info(f"Added new {server_data['protocol']} amplification server: "
                        f"{server_data['ip']}:{server_data['port']} "
                        f"(factor: {server_data['amplification_factor']})")
    
    def test_all_servers(self) -> None:
        """Test all stored amplification servers and update their status."""
        servers = self.storage.get_all_amplification_servers()
        if not servers:
            logger.info("No amplification servers to test")
            return
        
        logger.info(f"Testing {len(servers)} amplification servers")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {}
            
            for server_data in servers:
                try:
                    # Limit active threads
                    with self.thread_lock:
                        self.active_threads += 1
                    
                    protocol = server_data["protocol"]
                    ip = server_data["ip"]
                    port = server_data["port"]
                    
                    future = executor.submit(self._check_amplification, ip, protocol, port)
                    future.add_done_callback(self._thread_completed_callback)
                    futures[future] = server_data
                except Exception as e:
                    logger.error(f"Error setting up amplification server test: {e}")
            
            # Process results
            for future in concurrent.futures.as_completed(futures):
                server_data = futures[future]
                try:
                    result = future.result()
                    if result:
                        # Update with new results
                        server_data.update({
                            "working": True,
                            "amplification_factor": result["amplification_factor"],
                            "last_checked": time.time()
                        })
                    else:
                        # Server not working
                        server_data.update({
                            "working": False,
                            "last_checked": time.time()
                        })
                    
                    self.storage.update_amplification_server(server_data)
                except Exception as e:
                    logger.debug(f"Error processing amplification test result: {e}")
    
    # Protocol-specific test methods
    def _test_dns(self, ip: str, port: int) -> float:
        """Test for DNS amplification."""
        try:
            # Create a small DNS query packet asking for ANY record of a domain
            query = message.make_query(".", rdatatype.ANY)
            query_data = query.to_wire()
            query_size = len(query_data)
            
            # Create a socket for sending/receiving
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                
                # Send the query
                sock.sendto(query_data, (ip, port))
                
                # Receive response (up to 4096 bytes)
                response, _ = sock.recvfrom(4096)
                response_size = len(response)
                
                # Calculate amplification factor
                amplification = response_size / query_size
                
                return amplification
        except Exception as e:
            logger.debug(f"DNS amplification test failed for {ip}: {e}")
            return 0
    
    def _test_ntp(self, ip: str, port: int) -> float:
        """Test for NTP amplification."""
        try:
            # Create an NTP mode 6 (control) monlist request
            # Monlist command is known to cause amplification
            data = b'\x17\x00\x03\x2a' + b'\x00' * 8
            query_size = len(data)
            
            # Create a socket for sending/receiving
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                
                # Send the request
                sock.sendto(data, (ip, port))
                
                # Receive response (up to 4096 bytes)
                response = b''
                start_time = time.time()
                
                # Collect all responses within 2 seconds (there may be multiple packets)
                while time.time() - start_time < 2:
                    try:
                        data, _ = sock.recvfrom(4096)
                        response += data
                    except socket.timeout:
                        break
                
                response_size = len(response)
                
                # Calculate amplification factor
                amplification = response_size / query_size
                
                return amplification
        except Exception as e:
            logger.debug(f"NTP amplification test failed for {ip}: {e}")
            return 0
    
    def _test_cldap(self, ip: str, port: int) -> float:
        """Test for CLDAP amplification."""
        try:
            # CLDAP searchRequest message that triggers amplification
            data = bytes.fromhex(
                '30840000002d02010163840000002404000a01000400000000000f01000400000000000400'
                '00000301000a01000400000000')
            query_size = len(data)
            
            # Create a socket for sending/receiving
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                
                # Send the request
                sock.sendto(data, (ip, port))
                
                # Receive response (up to 4096 bytes)
                response, _ = sock.recvfrom(4096)
                response_size = len(response)
                
                # Calculate amplification factor
                amplification = response_size / query_size
                
                return amplification
        except Exception as e:
            logger.debug(f"CLDAP amplification test failed for {ip}: {e}")
            return 0
    
    def _test_memcached(self, ip: str, port: int) -> float:
        """Test for Memcached amplification."""
        try:
            # Memcached stats command (UDP)
            data = b'stats\r\n'
            query_size = len(data)
            
            # Create a socket for sending/receiving
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                
                # Send the request
                sock.sendto(data, (ip, port))
                
                # Receive response (up to 4096 bytes)
                response, _ = sock.recvfrom(4096)
                response_size = len(response)
                
                # Calculate amplification factor
                amplification = response_size / query_size
                
                return amplification
        except Exception as e:
            logger.debug(f"Memcached amplification test failed for {ip}: {e}")
            return 0
    
    def _test_chargen(self, ip: str, port: int) -> float:
        """Test for Chargen amplification."""
        try:
            # For chargen, any UDP packet will trigger a response
            data = b'\x00'
            query_size = len(data)
            
            # Create a socket for sending/receiving
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                
                # Send the request
                sock.sendto(data, (ip, port))
                
                # Receive response (up to 4096 bytes)
                response, _ = sock.recvfrom(4096)
                response_size = len(response)
                
                # Calculate amplification factor
                amplification = response_size / query_size
                
                return amplification
        except Exception as e:
            logger.debug(f"Chargen amplification test failed for {ip}: {e}")
            return 0
    
    def _test_ssdp(self, ip: str, port: int) -> float:
        """Test for SSDP amplification."""
        try:
            # SSDP discovery request
            data = (
                'M-SEARCH * HTTP/1.1\r\n'
                'HOST: 239.255.255.250:1900\r\n'
                'MAN: "ssdp:discover"\r\n'
                'MX: 1\r\n'
                'ST: ssdp:all\r\n\r\n'
            ).encode()
            query_size = len(data)
            
            # Create a socket for sending/receiving
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                
                # Send the request
                sock.sendto(data, (ip, port))
                
                # Receive response (up to 4096 bytes)
                response, _ = sock.recvfrom(4096)
                response_size = len(response)
                
                # Calculate amplification factor
                amplification = response_size / query_size
                
                return amplification
        except Exception as e:
            logger.debug(f"SSDP amplification test failed for {ip}: {e}")
            return 0
    
    def _test_quic(self, ip: str, port: int) -> float:
        """Test for QUIC amplification."""
        try:
            # A malformed QUIC Initial packet
            data = bytes.fromhex(
                'c6ff000001088394c8f03e5157080000449e00000002')
            query_size = len(data)
            
            # Create a socket for sending/receiving
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                
                # Send the request
                sock.sendto(data, (ip, port))
                
                # Receive response (up to 4096 bytes)
                response, _ = sock.recvfrom(4096)
                response_size = len(response)
                
                # Calculate amplification factor
                amplification = response_size / query_size
                
                return amplification
        except Exception as e:
            logger.debug(f"QUIC amplification test failed for {ip}: {e}")
            return 0
    
    def _test_tftp(self, ip: str, port: int) -> float:
        """Test for TFTP amplification."""
        try:
            # TFTP read request for a non-existent file
            # Opcode 1 (RRQ), file "test", mode "netascii"
            data = b'\x00\x01test\x00netascii\x00'
            query_size = len(data)
            
            # Create a socket for sending/receiving
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                
                # Send the request
                sock.sendto(data, (ip, port))
                
                # Receive response (up to 4096 bytes)
                response, _ = sock.recvfrom(4096)
                response_size = len(response)
                
                # Calculate amplification factor
                amplification = response_size / query_size
                
                return amplification
        except Exception as e:
            logger.debug(f"TFTP amplification test failed for {ip}: {e}")
            return 0
    
    def _test_portmap(self, ip: str, port: int) -> float:
        """Test for Portmap amplification."""
        try:
            # Portmap dump call
            # XID, Call, Portmap program, version 2, procedure 4 (dump)
            data = bytes.fromhex(
                '12345678000000000000000000000002000186A00000000200000004'
                '0000000000000000000000000000000000000000')
            query_size = len(data)
            
            # Create a socket for sending/receiving
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                
                # Send the request
                sock.sendto(data, (ip, port))
                
                # Receive response (up to 4096 bytes)
                response, _ = sock.recvfrom(4096)
                response_size = len(response)
                
                # Calculate amplification factor
                amplification = response_size / query_size
                
                return amplification
        except Exception as e:
            logger.debug(f"Portmap amplification test failed for {ip}: {e}")
            return 0
    
    def _test_qotd(self, ip: str, port: int) -> float:
        """Test for QOTD (Quote of the Day) amplification."""
        try:
            # Any UDP packet will trigger a QOTD response
            data = b'\x00'
            query_size = len(data)
            
            # Create a socket for sending/receiving
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                
                # Send the request
                sock.sendto(data, (ip, port))
                
                # Receive response (up to 4096 bytes)
                response, _ = sock.recvfrom(4096)
                response_size = len(response)
                
                # Calculate amplification factor
                amplification = response_size / query_size
                
                return amplification
        except Exception as e:
            logger.debug(f"QOTD amplification test failed for {ip}: {e}")
            return 0
    
    def _test_snmp(self, ip: str, port: int) -> float:
        """Test for SNMP amplification."""
        try:
            # SNMP v2c GetBulkRequest for system MIB
            data = bytes.fromhex(
                '302902010104067075626c6963a51c02041b5e52ef0201000201003011'
                '3009060500f2eb1a05010500')
            query_size = len(data)
            
            # Create a socket for sending/receiving
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                
                # Send the request
                sock.sendto(data, (ip, port))
                
                # Receive response (up to 4096 bytes)
                response, _ = sock.recvfrom(4096)
                response_size = len(response)
                
                # Calculate amplification factor
                amplification = response_size / query_size
                
                return amplification
        except Exception as e:
            logger.debug(f"SNMP amplification test failed for {ip}: {e}")
            return 0
