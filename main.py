#!/usr/bin/env python3

import argparse
import logging
import os
import sys
from pathlib import Path

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.ui import MainUI
from modules.proxy_scanner import ProxyScanner
from modules.amplification_scanner import AmplificationScanner
from modules.attack_methods import Layer4, Layer7
from modules.storage import Storage

# Import Flask app for web interface
from app import app

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("NetSecTest")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Ethical Network Security Testing Framework",
        epilog="This tool is for authorized security testing only."
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--skip-disclaimer", action="store_true", help="Skip the legal disclaimer")
    parser.add_argument("--scan-only", action="store_true", help="Only scan for proxies and amplification servers")
    
    return parser.parse_args()

def show_disclaimer():
    """Display legal disclaimer and require acceptance."""
    disclaimer = """
    LEGAL DISCLAIMER AND TERMS OF USE
    
    This tool is provided for AUTHORIZED SECURITY TESTING ONLY.
    
    By using this software, you agree to:
    1. Only use it against systems you own or have explicit permission to test
    2. Comply with all applicable laws and regulations
    3. Take full responsibility for any consequences of your actions
    
    Unauthorized use of this tool against systems without permission
    may violate computer crime laws and result in criminal charges.
    
    Do you accept these terms and confirm you have proper authorization? (yes/no): """
    
    response = input(disclaimer).lower().strip()
    if response != "yes":
        logger.critical("Terms not accepted. Exiting.")
        sys.exit(1)
    
    logger.info("Disclaimer accepted. Proceeding with initialization.")

def main():
    """Main entry point for the application."""
    args = parse_args()
    
    # Set logging level based on verbosity flag
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Show legal disclaimer unless skipped
    if not args.skip_disclaimer:
        show_disclaimer()
    
    # Ensure data directories exist
    Path("data").mkdir(exist_ok=True)
    
    # Initialize storage for proxies and amplification servers
    storage = Storage()
    
    # Initialize scanners
    proxy_scanner = ProxyScanner(storage)
    amp_scanner = AmplificationScanner(storage)
    
    # Initialize attack methods
    layer4 = Layer4(storage)
    layer7 = Layer7(storage)
    
    # Try to start the Terminal UI, but fallback to web interface if it fails
    try:
        ui = MainUI(proxy_scanner, amp_scanner, layer4, layer7, storage)
        ui.start()
    except Exception as e:
        logger.error(f"Unable to start the text UI: {e}")
        print("=" * 50)
        print(f"Terminal UI Error:\nUnable to start the text UI: {e}")
        print("This may be due to terminal limitations or incompatible environment.")
        print("You can still use the web interface at http://localhost:5000")
        print("=" * 50)
        
        # Start passive scanning if requested
        if args.scan_only:
            print("Starting passive scanning as requested...")
            if not proxy_scanner.scanning:
                proxy_scanner.start_scanning()
            if not amp_scanner.scanning:
                amp_scanner.start_scanning()
            
            try:
                # Keep the process running
                import time
                while True:
                    time.sleep(60)  # Sleep for 60 seconds
                    logger.info(f"Proxies found: {storage.get_proxy_count()}, Working: {len(storage.get_working_proxies())}")
                    logger.info(f"Amplification servers found: {storage.get_amplification_server_count()}, Working: {len(storage.get_working_amplification_servers())}")
            except KeyboardInterrupt:
                logger.info("Received keyboard interrupt. Shutting down scanners...")
                proxy_scanner.stop_scanning()
                amp_scanner.stop_scanning()
        else:
            # Keep the process running for the web interface
            try:
                print("Press Ctrl+C to exit.")
                while True:
                    import time
                    time.sleep(60)  # Sleep for 60 seconds
            except KeyboardInterrupt:
                logger.info("Received keyboard interrupt. Shutting down...")
                proxy_scanner.stop_scanning()
                amp_scanner.stop_scanning()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt. Shutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Unexpected error: {e}")
        sys.exit(1)
