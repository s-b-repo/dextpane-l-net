#!/usr/bin/env python3

import concurrent.futures
import ipaddress
import logging
import random
import socket
import threading
import time
import requests
from typing import Dict, List, Tuple, Any, Optional, Set
import urllib.parse

# Custom proxy handling classes
class ProxyType:
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SOCKS4 = "SOCKS4"
    SOCKS5 = "SOCKS5"

class Proxy:
    def __init__(self, proxy_type, host, port, timeout=10):
        self.type = proxy_type
        self.host = host
        self.port = port
        self.timeout = timeout
        
    def get_dict(self):
        proxy_url = f"{self.host}:{self.port}"
        if self.type == ProxyType.HTTP:
            return {"http": f"http://{proxy_url}"}
        elif self.type == ProxyType.HTTPS:
            return {"https": f"https://{proxy_url}"}
        elif self.type == ProxyType.SOCKS4:
            return {"http": f"socks4://{proxy_url}", "https": f"socks4://{proxy_url}"}
        elif self.type == ProxyType.SOCKS5:
            return {"http": f"socks5://{proxy_url}", "https": f"socks5://{proxy_url}"}
        return {}
    
    def get(self, url):
        try:
            response = requests.get(url, proxies=self.get_dict(), timeout=self.timeout)
            return response
        except Exception as e:
            return None

class ProxyUtiles:
    @staticmethod
    def download_from_resources(sources):
        proxies = []
        for source in sources:
            try:
                response = requests.get(source, timeout=10)
                if response.status_code == 200:
                    lines = response.text.split('\n')
                    for line in lines:
                        if ':' in line:
                            parts = line.strip().split(':')
                            if len(parts) >= 2:
                                ip = parts[0]
                                port = int(parts[1])
                                
                                # Determine proxy type from filename
                                proxy_type = ProxyType.HTTP
                                if "socks4" in source.lower():
                                    proxy_type = ProxyType.SOCKS4
                                elif "socks5" in source.lower():
                                    proxy_type = ProxyType.SOCKS5
                                
                                proxies.append(Proxy(proxy_type, ip, port))
            except Exception as e:
                pass
        return proxies

logger = logging.getLogger("NetSecTest.ProxyScanner")

class ProxyScanner:
    """Scanner for discovering and testing web proxies."""
    
    def __init__(self, storage):
        """Initialize the proxy scanner."""
        self.storage = storage
        self.scanning = False
        self.scan_thread = None
        self.max_threads = 100  # Default thread count
        self.active_threads = 0
        self.thread_lock = threading.Lock()
        self.target_test_url = "http://www.google.com"  # URL for testing proxies
        self.scan_count = 0  # Count of scans performed
        self.found_proxies_count = 0  # Count of found proxies
        
        # Common proxy ports
        self.proxy_ports = [
            80, 8080, 3128, 8000, 8888, 1080, 3129, 8081, 9080, 
            8181, 8090, 9090, 5555, 4444, 8118, 53281, 9999, 9001,
            3333, 3389, 4145, 4153, 9150, 9051, 54321, 1081, 1082
        ]
        
        # Networks to scan (extended list)
        self.networks_to_scan = [
            "194.5.0.0/16",    # Known proxy range
            "192.111.0.0/16",  # Known proxy range
            "146.59.0.0/16",   # OVH cloud
            "51.250.0.0/16",   # Yandex cloud
            "178.128.0.0/16",  # DigitalOcean
            "157.245.0.0/16",  # DigitalOcean
            "138.197.0.0/16",  # DigitalOcean
            "167.99.0.0/16",   # DigitalOcean
            "134.209.0.0/16",  # DigitalOcean
            "104.131.0.0/16",  # DigitalOcean
            "159.203.0.0/16",  # DigitalOcean
            "147.182.0.0/16",  # DigitalOcean
            "165.22.0.0/16",   # DigitalOcean
            "142.93.0.0/16",   # DigitalOcean
            "45.76.0.0/16",    # Vultr
            "45.32.0.0/16",    # Vultr
            "45.63.0.0/16",    # Vultr
            "45.77.0.0/16",    # Vultr
            "149.28.0.0/16",   # Vultr
            "95.179.0.0/16",   # Datacamp
            "31.14.0.0/16",    # Host Sailor
            "5.42.0.0/16",     # Host Sailor
            "92.222.0.0/16",   # OVH
            "193.58.0.0/16",   # Host Sailor
            "45.155.0.0/16",   # Host Sailor
            "64.0.0.0/8",      # Various providers
            "192.169.0.0/16",  # Limestone
            "183.88.0.0/16",   # Thai providers
            "103.0.0.0/8",     # Asian providers
            "185.0.0.0/8",     # European providers
            "201.0.0.0/8"      # Latin American providers
        ]
        
        # Public proxy sources (extended list for improved discovery)
        self.proxy_sources = [
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
            "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
            "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
            "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt"
        ]
        
        # Initialize scanned IPs set
        self.scanned_ips = set()
    
    def start_scanning(self) -> None:
        """Start the continuous proxy scanning process."""
        if self.scanning:
            logger.warning("Proxy scanning already running")
            return
        
        self.scanning = True
        self.scan_thread = threading.Thread(target=self._scanning_thread, daemon=True)
        self.scan_thread.start()
        logger.info("Proxy scanning started")
    
    def stop_scanning(self) -> None:
        """Stop the continuous proxy scanning process."""
        if not self.scanning:
            logger.warning("Proxy scanning not running")
            return
        
        self.scanning = False
        if self.scan_thread:
            # Allow the thread to finish naturally
            self.scan_thread.join(timeout=2)
            self.scan_thread = None
        logger.info("Proxy scanning stopped")
    
    def get_thread_count(self) -> int:
        """Get the current number of active scanning threads."""
        return self.active_threads
    
    def set_max_threads(self, count: int) -> None:
        """Set the maximum number of concurrent scanning threads."""
        self.max_threads = max(1, min(500, count))  # Limit between 1 and 500
    
    def get_scan_stats(self) -> Dict[str, Any]:
        """Get scanning statistics."""
        return {
            "total_scans": self.scan_count,
            "found_proxies": self.found_proxies_count,
            "active_threads": self.active_threads,
            "scanned_ips": len(self.scanned_ips)
        }
    
    def _scanning_thread(self) -> None:
        """Main scanning thread that runs continuously while scanning is enabled."""
        while self.scanning:
            try:
                # Randomly choose between different scanning methods
                scan_choice = random.randint(1, 10)
                
                if scan_choice <= 6:  # 60% chance for random IP scanning
                    # Method 1: Scan random IPs from selected networks
                    self._scan_random_ips(100)  # Scan 100 random IPs
                    self.scan_count += 1
                elif scan_choice <= 9:  # 30% chance for public sources
                    # Method 2: Fetch from public proxy lists
                    self._fetch_from_public_sources()
                    self.scan_count += 1
                else:  # 10% chance for testing existing
                    # Method 3: Test existing proxies to update their status
                    self.test_all_proxies()
                
                # Sleep between scan batches (shorter time for faster discovery)
                time.sleep(5)
            except Exception as e:
                logger.error(f"Error in scanning thread: {e}")
                time.sleep(30)  # Longer sleep on error
    
    def _scan_random_ips(self, count: int) -> None:
        """Scan random IPs from the networks list for open proxy ports."""
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
            
            # Skip already scanned IPs
            if ip in self.scanned_ips:
                continue
            
            self.scanned_ips.add(ip)
            
            # Add random port combinations to scan
            ports = random.sample(self.proxy_ports, min(5, len(self.proxy_ports)))
            for port in ports:
                targets.append((ip, port))
        
        # Scan the targets
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            
            for ip, port in targets:
                # Limit active threads
                with self.thread_lock:
                    self.active_threads += 1
                
                future = executor.submit(self._check_proxy, ip, port)
                future.add_done_callback(self._thread_completed_callback)
                futures.append(future)
            
            # Wait for all futures to complete
            for future in concurrent.futures.as_completed(futures):
                try:
                    proxy = future.result()
                    if proxy:
                        self._save_proxy(proxy)
                        with self.thread_lock:
                            self.found_proxies_count += 1
                except Exception as e:
                    logger.debug(f"Error checking proxy: {e}")
    
    def _thread_completed_callback(self, future):
        """Callback when a thread is completed to decrement active thread count."""
        with self.thread_lock:
            self.active_threads -= 1
    
    def _fetch_from_public_sources(self) -> None:
        """Fetch proxies from public proxy lists."""
        try:
            # Pick random sources (multiple sources for better efficiency)
            sources = random.sample(self.proxy_sources, min(3, len(self.proxy_sources)))
            logger.debug(f"Fetching proxies from {len(sources)} sources")
            
            # Use our custom utility to fetch proxies
            proxies = ProxyUtiles.download_from_resources(sources)
            if not proxies:
                logger.warning(f"No proxies found from public sources")
                return
            
            logger.info(f"Downloaded {len(proxies)} proxies from public sources")
            
            # Test a subset of the downloaded proxies
            test_count = min(50, len(proxies))
            proxies_to_test = random.sample(proxies, test_count)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                
                for proxy in proxies_to_test:
                    # Limit active threads
                    with self.thread_lock:
                        self.active_threads += 1
                    
                    future = executor.submit(self._check_proxy_object, proxy)
                    future.add_done_callback(self._thread_completed_callback)
                    futures.append(future)
                
                # Wait for all futures to complete
                successful_proxies = 0
                for future in concurrent.futures.as_completed(futures):
                    try:
                        proxy = future.result()
                        if proxy:
                            self._save_proxy(proxy)
                            successful_proxies += 1
                            with self.thread_lock:
                                self.found_proxies_count += 1
                    except Exception as e:
                        logger.debug(f"Error checking proxy: {e}")
                
                logger.info(f"Found {successful_proxies} working proxies from public sources")
        
        except Exception as e:
            logger.error(f"Error fetching from public sources: {e}")
    
    def _check_proxy(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Check if the given IP and port is a working proxy."""
        # Try different proxy types
        for proxy_type in [ProxyType.HTTP, ProxyType.SOCKS4, ProxyType.SOCKS5]:
            try:
                proxy = Proxy(proxy_type, ip, port)
                if self._test_proxy(proxy):
                    return {
                        "ip": ip,
                        "port": port,
                        "type": proxy_type,
                        "country": self._get_country(ip),
                        "working": True,
                        "last_checked": time.time(),
                        "response_time": proxy.timeout,
                        "anonymity": self._check_anonymity(proxy)
                    }
            except Exception as e:
                logger.debug(f"Error checking {ip}:{port} as {proxy_type}: {e}")
        
        return None
    
    def _check_proxy_object(self, proxy: Proxy) -> Optional[Dict[str, Any]]:
        """Check if the given Proxy object is working."""
        try:
            if self._test_proxy(proxy):
                return {
                    "ip": proxy.host,
                    "port": proxy.port,
                    "type": proxy.type,
                    "country": self._get_country(proxy.host),
                    "working": True,
                    "last_checked": time.time(),
                    "response_time": proxy.timeout,
                    "anonymity": self._check_anonymity(proxy)
                }
        except Exception as e:
            logger.debug(f"Error checking proxy {proxy.host}:{proxy.port}: {e}")
        
        return None
    
    def _test_proxy(self, proxy: Proxy) -> bool:
        """Test if a proxy is working by making a request through it."""
        try:
            # Set a timeout for the test
            proxy.timeout = 5  # Increased timeout for better reliability
            
            # Try to connect to the test URL through the proxy
            start_time = time.time()
            response = proxy.get(self.target_test_url)
            end_time = time.time()
            
            # Store the response time
            response_time = end_time - start_time
            # Use an integer timeout for compatibility
            proxy.timeout = int(response_time * 1000) # milliseconds as int
            
            # Check if we received a valid response
            if response and response.status_code < 400:
                logger.debug(f"Found working proxy: {proxy.host}:{proxy.port} ({proxy.type})")
                return True
        except Exception as e:
            logger.debug(f"Proxy test failed for {proxy.host}:{proxy.port}: {e}")
        
        return False
    
    def _check_anonymity(self, proxy: Proxy) -> str:
        """Check the anonymity level of a proxy."""
        try:
            # For simplicity, we're just returning "Unknown"
            # In a real implementation, this would check IP headers to determine if the proxy
            # is transparent, anonymous, or elite (high-anonymous)
            return "Unknown"
        except Exception:
            return "Unknown"
    
    def _get_country(self, ip: str) -> str:
        """Try to determine the country of an IP address."""
        try:
            # Try to get the country via a free IP lookup service
            # In production, consider using a local database like MaxMind GeoIP
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
            if response.status_code == 200:
                data = response.json()
                if "country" in data:
                    return data["country"]
        except Exception:
            pass
        
        return "Unknown"
    
    def _save_proxy(self, proxy_data: Dict[str, Any]) -> None:
        """Save a discovered proxy to storage."""
        # Check if this proxy already exists
        existing = self.storage.find_proxy(proxy_data["ip"], proxy_data["port"])
        
        if existing:
            # Update the existing proxy
            existing.update({
                "working": proxy_data["working"],
                "last_checked": proxy_data["last_checked"]
            })
            self.storage.update_proxy(existing)
        else:
            # Add the new proxy
            self.storage.add_proxy(proxy_data)
            logger.info(f"Added new proxy: {proxy_data['ip']}:{proxy_data['port']} ({proxy_data['type']})")
    
    def test_all_proxies(self) -> None:
        """Test all stored proxies and update their status."""
        proxies = self.storage.get_all_proxies()
        if not proxies:
            logger.info("No proxies to test")
            return
        
        logger.info(f"Testing {len(proxies)} proxies")
        working_before = len([p for p in proxies if p.get("working", False)])
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {}
            
            for proxy_data in proxies:
                try:
                    # Create a Proxy object from the stored data
                    proxy = Proxy(
                        proxy_data["type"], 
                        proxy_data["ip"], 
                        proxy_data["port"]
                    )
                    
                    # Limit active threads
                    with self.thread_lock:
                        self.active_threads += 1
                    
                    future = executor.submit(self._test_proxy, proxy)
                    future.add_done_callback(self._thread_completed_callback)
                    futures[future] = proxy_data
                except Exception as e:
                    logger.error(f"Error setting up proxy test: {e}")
            
            # Process results
            for future in concurrent.futures.as_completed(futures):
                proxy_data = futures[future]
                try:
                    is_working = future.result()
                    # Update the proxy status
                    proxy_data["working"] = is_working
                    proxy_data["last_checked"] = time.time()
                    self.storage.update_proxy(proxy_data)
                except Exception as e:
                    logger.debug(f"Error processing proxy test result: {e}")
        
        # Report results
        proxies = self.storage.get_all_proxies()
        working_after = len([p for p in proxies if p.get("working", False)])
        logger.info(f"Proxy test completed: {working_after}/{len(proxies)} working proxies " +
                    f"({working_after - working_before:+d} change)")
                    
    def get_best_proxies(self, count: int = 10) -> List[Dict[str, Any]]:
        """Get the best working proxies based on response time."""
        proxies = self.storage.get_working_proxies()
        if not proxies:
            return []
            
        # Sort by response time (faster proxies first)
        sorted_proxies = sorted(proxies, key=lambda p: p.get("response_time", float('inf')))
        return sorted_proxies[:count]
