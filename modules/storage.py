#!/usr/bin/env python3

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger("NetSecTest.Storage")

class Storage:
    """Storage for proxies and amplification servers."""
    
    def __init__(self, auto_save=True, auto_save_interval=60):
        """Initialize the storage."""
        self.proxies = []
        self.amplification_servers = []
        
        self.proxies_lock = threading.Lock()
        self.servers_lock = threading.Lock()
        
        self.auto_save = auto_save
        self.auto_save_interval = auto_save_interval
        
        # Path for data files
        self.proxies_file = Path("data/proxies.json")
        self.servers_file = Path("data/amplification_servers.json")
        
        # Create data directory if it doesn't exist
        Path("data").mkdir(exist_ok=True)
        
        # Load existing data
        self._load_data()
        
        # Start auto-save thread if enabled
        if self.auto_save:
            self.running = True
            self.save_thread = threading.Thread(target=self._auto_save_thread, daemon=True)
            self.save_thread.start()
    
    def _auto_save_thread(self):
        """Thread for automatically saving data periodically."""
        while self.running:
            time.sleep(self.auto_save_interval)
            self.save_all()
    
    def _load_data(self):
        """Load data from files."""
        # Load proxies
        if self.proxies_file.exists():
            try:
                with open(self.proxies_file, "r") as f:
                    self.proxies = json.load(f)
                logger.info(f"Loaded {len(self.proxies)} proxies from storage")
            except Exception as e:
                logger.error(f"Error loading proxies: {e}")
                self.proxies = []
        
        # Load amplification servers
        if self.servers_file.exists():
            try:
                with open(self.servers_file, "r") as f:
                    self.amplification_servers = json.load(f)
                logger.info(f"Loaded {len(self.amplification_servers)} amplification servers from storage")
            except Exception as e:
                logger.error(f"Error loading amplification servers: {e}")
                self.amplification_servers = []
    
    def save_all(self):
        """Save all data to files."""
        self.save_proxies()
        self.save_amplification_servers()
    
    def save_proxies(self):
        """Save proxies to file."""
        try:
            with self.proxies_lock:
                with open(self.proxies_file, "w") as f:
                    json.dump(self.proxies, f, indent=2)
            logger.debug(f"Saved {len(self.proxies)} proxies to storage")
        except Exception as e:
            logger.error(f"Error saving proxies: {e}")
    
    def save_amplification_servers(self):
        """Save amplification servers to file."""
        try:
            with self.servers_lock:
                with open(self.servers_file, "w") as f:
                    json.dump(self.amplification_servers, f, indent=2)
            logger.debug(f"Saved {len(self.amplification_servers)} amplification servers to storage")
        except Exception as e:
            logger.error(f"Error saving amplification servers: {e}")
    
    # Proxy methods
    def add_proxy(self, proxy_data: Dict[str, Any]) -> bool:
        """Add a new proxy to storage."""
        with self.proxies_lock:
            # Check if already exists
            for existing in self.proxies:
                if (existing["ip"] == proxy_data["ip"] and 
                    existing["port"] == proxy_data["port"] and
                    existing["type"] == proxy_data["type"]):
                    return False
            
            # Add the new proxy
            self.proxies.append(proxy_data)
            return True
    
    def update_proxy(self, proxy_data: Dict[str, Any]) -> bool:
        """Update an existing proxy in storage."""
        with self.proxies_lock:
            for i, existing in enumerate(self.proxies):
                if (existing["ip"] == proxy_data["ip"] and 
                    existing["port"] == proxy_data["port"] and
                    existing["type"] == proxy_data["type"]):
                    # Update the proxy
                    self.proxies[i] = proxy_data
                    return True
            
            # Not found
            return False
    
    def remove_proxy(self, ip: str, port: int, proxy_type: str) -> bool:
        """Remove a proxy from storage."""
        with self.proxies_lock:
            for i, existing in enumerate(self.proxies):
                if (existing["ip"] == ip and 
                    existing["port"] == port and
                    existing["type"] == proxy_type):
                    # Remove the proxy
                    del self.proxies[i]
                    return True
            
            # Not found
            return False
    
    def find_proxy(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Find a proxy by IP and port."""
        with self.proxies_lock:
            for existing in self.proxies:
                if existing["ip"] == ip and existing["port"] == port:
                    return existing
            
            # Not found
            return None
    
    def get_all_proxies(self) -> List[Dict[str, Any]]:
        """Get all proxies."""
        with self.proxies_lock:
            return self.proxies.copy()
    
    def get_working_proxies(self) -> List[Dict[str, Any]]:
        """Get all working proxies."""
        with self.proxies_lock:
            return [p for p in self.proxies if p.get("working", False)]
    
    def get_proxy_count(self) -> int:
        """Get the total number of proxies."""
        with self.proxies_lock:
            return len(self.proxies)
    
    def clear_proxies(self) -> None:
        """Remove all proxies."""
        with self.proxies_lock:
            self.proxies = []
    
    # Amplification server methods
    def add_amplification_server(self, server_data: Dict[str, Any]) -> bool:
        """Add a new amplification server to storage."""
        with self.servers_lock:
            # Check if already exists
            for existing in self.amplification_servers:
                if (existing["ip"] == server_data["ip"] and 
                    existing["protocol"] == server_data["protocol"]):
                    return False
            
            # Add the new server
            self.amplification_servers.append(server_data)
            return True
    
    def update_amplification_server(self, server_data: Dict[str, Any]) -> bool:
        """Update an existing amplification server in storage."""
        with self.servers_lock:
            for i, existing in enumerate(self.amplification_servers):
                if (existing["ip"] == server_data["ip"] and 
                    existing["protocol"] == server_data["protocol"]):
                    # Update the server
                    self.amplification_servers[i] = server_data
                    return True
            
            # Not found
            return False
    
    def remove_amplification_server(self, ip: str, protocol: str) -> bool:
        """Remove an amplification server from storage."""
        with self.servers_lock:
            for i, existing in enumerate(self.amplification_servers):
                if (existing["ip"] == ip and 
                    existing["protocol"] == protocol):
                    # Remove the server
                    del self.amplification_servers[i]
                    return True
            
            # Not found
            return False
    
    def find_amplification_server(self, ip: str, protocol: str) -> Optional[Dict[str, Any]]:
        """Find an amplification server by IP and protocol."""
        with self.servers_lock:
            for existing in self.amplification_servers:
                if existing["ip"] == ip and existing["protocol"] == protocol:
                    return existing
            
            # Not found
            return None
    
    def get_all_amplification_servers(self) -> List[Dict[str, Any]]:
        """Get all amplification servers."""
        with self.servers_lock:
            return self.amplification_servers.copy()
    
    def get_working_amplification_servers(self, protocol: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all working amplification servers, optionally filtered by protocol."""
        with self.servers_lock:
            if protocol:
                return [s for s in self.amplification_servers 
                        if s.get("working", False) and s["protocol"] == protocol]
            else:
                return [s for s in self.amplification_servers if s.get("working", False)]
    
    def get_amplification_server_count(self) -> int:
        """Get the total number of amplification servers."""
        with self.servers_lock:
            return len(self.amplification_servers)
    
    def clear_amplification_servers(self) -> None:
        """Remove all amplification servers."""
        with self.servers_lock:
            self.amplification_servers = []
