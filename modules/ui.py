#!/usr/bin/env python3

import curses
import logging
import threading
import time
from typing import Dict, List, Any

logger = logging.getLogger("NetSecTest.UI")

class MenuOption:
    """Represents a menu option with a callback function."""
    def __init__(self, name, callback, description=""):
        self.name = name
        self.callback = callback
        self.description = description

class CheckboxOption:
    """Represents a checkbox option that can be toggled."""
    def __init__(self, name, description="", checked=False):
        self.name = name
        self.description = description
        self.checked = checked

class MainUI:
    """Main user interface for the network security testing tool."""
    
    def __init__(self, proxy_scanner, amp_scanner, layer4, layer7, storage):
        """Initialize the UI with the necessary components."""
        self.proxy_scanner = proxy_scanner
        self.amp_scanner = amp_scanner
        self.layer4 = layer4
        self.layer7 = layer7
        self.storage = storage
        
        self.screen = None
        self.current_menu = "main"
        self.selected_index = 0
        self.running = True
        self.status_message = ""
        self.status_color = 0
        
        # Stats
        self.stats = {
            "proxies_total": 0,
            "proxies_working": 0,
            "amp_servers_total": 0,
            "amp_servers_working": 0,
            "attacks_running": 0,
            "scan_threads_proxy": 0,
            "scan_threads_amp": 0
        }
        
        # Thread control
        self.proxy_scanning_active = False
        self.amp_scanning_active = False
        
        # Checkbox options
        self.checkboxes = {
            "use_proxies": CheckboxOption("Use Proxies", "Use discovered proxies for attacks", True),
            "use_amplification": CheckboxOption("Use Amplification", "Use discovered amplification servers", True),
            "auto_remove_dead": CheckboxOption("Auto-remove Dead", "Automatically remove non-responsive proxies", True),
            "ethical_mode": CheckboxOption("Ethical Mode", "Enforce ethical guidelines", True)
        }
        
        # Main menu options
        self.menus = {
            "main": [
                MenuOption("Proxy Scanner", self.show_proxy_menu, "Scan for and manage proxies"),
                MenuOption("Amplification Scanner", self.show_amp_menu, "Scan for and manage amplification servers"),
                MenuOption("Layer 4 Testing", self.show_layer4_menu, "Layer 4 network security testing"),
                MenuOption("Layer 7 Testing", self.show_layer7_menu, "Layer 7 application security testing"),
                MenuOption("Settings", self.show_settings_menu, "Configure application settings"),
                MenuOption("Quit", self.quit, "Exit the application")
            ],
            "proxy": [
                MenuOption("Start Proxy Scanning", self.toggle_proxy_scanning, "Begin continuous proxy scanning"),
                MenuOption("Test Existing Proxies", self.test_existing_proxies, "Verify existing proxies"),
                MenuOption("View Proxies", self.view_proxies, "View discovered proxies"),
                MenuOption("Import Proxies", self.import_proxies, "Import proxies from file"),
                MenuOption("Export Proxies", self.export_proxies, "Export proxies to file"),
                MenuOption("Clear Proxies", self.clear_proxies, "Remove all proxies"),
                MenuOption("Back", lambda: self.change_menu("main"), "Return to main menu")
            ],
            "amplification": [
                MenuOption("Start Amplification Scanning", self.toggle_amp_scanning, "Begin amplification server scanning"),
                MenuOption("Test Existing Servers", self.test_existing_amps, "Verify existing amplification servers"),
                MenuOption("View Amplification Servers", self.view_amp_servers, "View discovered servers"),
                MenuOption("Import Servers", self.import_amp_servers, "Import servers from file"),
                MenuOption("Export Servers", self.export_amp_servers, "Export servers to file"),
                MenuOption("Clear Servers", self.clear_amp_servers, "Remove all servers"),
                MenuOption("Back", lambda: self.change_menu("main"), "Return to main menu")
            ],
            "layer4": [
                MenuOption("UDP Flood", lambda: self.start_attack("UDP"), "UDP packet flood"),
                MenuOption("TCP Flood", lambda: self.start_attack("TCP"), "TCP connection flood"),
                MenuOption("SYN Flood", lambda: self.start_attack("SYN"), "TCP SYN packet flood"),
                MenuOption("ICMP Flood", lambda: self.start_attack("ICMP"), "ICMP echo request flood"),
                MenuOption("DNS Amplification", lambda: self.start_attack("DNS"), "DNS amplification attack"),
                MenuOption("NTP Amplification", lambda: self.start_attack("NTP"), "NTP amplification attack"),
                MenuOption("CLDAP Amplification", lambda: self.start_attack("CLDAP"), "CLDAP amplification attack"),
                MenuOption("Stop All Attacks", self.stop_all_attacks, "Stop all running attacks"),
                MenuOption("Back", lambda: self.change_menu("main"), "Return to main menu")
            ],
            "layer7": [
                MenuOption("HTTP GET Flood", lambda: self.start_attack("GET"), "HTTP GET request flood"),
                MenuOption("HTTP POST Flood", lambda: self.start_attack("POST"), "HTTP POST request flood"),
                MenuOption("Slow Loris", lambda: self.start_attack("SLOW"), "Slow HTTP request attack"),
                MenuOption("HTTP HEAD Flood", lambda: self.start_attack("HEAD"), "HTTP HEAD request flood"),
                MenuOption("Stop All Attacks", self.stop_all_attacks, "Stop all running attacks"),
                MenuOption("Back", lambda: self.change_menu("main"), "Return to main menu")
            ],
            "settings": [
                MenuOption("Toggle Use Proxies", lambda: self.toggle_checkbox("use_proxies"), 
                           "Enable/disable proxy usage for attacks"),
                MenuOption("Toggle Use Amplification", lambda: self.toggle_checkbox("use_amplification"), 
                           "Enable/disable amplification server usage"),
                MenuOption("Toggle Auto-Remove Dead", lambda: self.toggle_checkbox("auto_remove_dead"), 
                           "Enable/disable automatic removal of dead proxies"),
                MenuOption("Toggle Ethical Mode", lambda: self.toggle_checkbox("ethical_mode"), 
                           "Enable/disable ethical restrictions"),
                MenuOption("Threads Configuration", self.configure_threads, "Configure thread counts"),
                MenuOption("Back", lambda: self.change_menu("main"), "Return to main menu")
            ]
        }
        
        # Status update thread
        self.status_thread = threading.Thread(target=self.update_stats_thread, daemon=True)
    
    def start(self):
        """Start the UI."""
        # Check if running in a compatible terminal
        try:
            # Try to initialize curses to see if it's compatible
            stdscr = curses.initscr()
            curses.endwin()  # Clean up before proper initialization
            
            # Start curses application with wrapper for proper cleanup
            curses.wrapper(self.main_loop)
        except Exception as e:
            logger.error(f"UI error: {e}")
            print("\n" + "="*50)
            print("Terminal UI Error:")
            print(f"Unable to start the text UI: {e}")
            print("This may be due to terminal limitations or incompatible environment.")
            print("You can still use the web interface at http://localhost:5000")
            print("="*50 + "\n")
            # Exit gracefully instead of raising an exception
            return
    
    def main_loop(self, stdscr):
        """Main UI loop."""
        self.screen = stdscr
        
        # Configure curses
        curses.curs_set(0)  # Hide cursor
        curses.start_color()
        curses.use_default_colors()
        
        # Initialize color pairs
        curses.init_pair(1, curses.COLOR_GREEN, -1)  # Success
        curses.init_pair(2, curses.COLOR_RED, -1)    # Error
        curses.init_pair(3, curses.COLOR_YELLOW, -1) # Warning
        curses.init_pair(4, curses.COLOR_CYAN, -1)   # Info
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)  # Selected
        
        # Start status update thread
        self.status_thread.start()
        
        # Main loop
        while self.running:
            self.screen.clear()
            self.draw_ui()
            self.handle_input()
            self.screen.refresh()
            time.sleep(0.05)  # Small delay to reduce CPU usage
    
    def draw_ui(self):
        """Draw the UI components."""
        height, width = self.screen.getmaxyx()
        
        # Draw header
        self.screen.addstr(0, 0, "Ethical Network Security Testing Framework", curses.A_BOLD)
        self.screen.addstr(1, 0, "=" * (width - 1))
        
        # Draw status bar
        self.draw_status_bar(height - 2, width)
        
        # Draw menu
        self.draw_menu(3, width)
        
        # Draw statistics panel
        self.draw_stats_panel(3, width)
    
    def draw_menu(self, start_y, width):
        """Draw the current menu."""
        # Draw menu title
        menu_title = f"{self.current_menu.capitalize()} Menu"
        self.screen.addstr(start_y, 2, menu_title, curses.A_BOLD)
        self.screen.addstr(start_y + 1, 2, "-" * len(menu_title))
        
        # Draw menu options
        for i, option in enumerate(self.menus[self.current_menu]):
            y_pos = start_y + 3 + i
            
            # Highlight selected option
            if i == self.selected_index:
                self.screen.attron(curses.color_pair(5) | curses.A_BOLD)
                self.screen.addstr(y_pos, 2, f"> {option.name}")
                self.screen.attroff(curses.color_pair(5) | curses.A_BOLD)
                
                # Show description for selected option
                if option.description:
                    self.screen.addstr(y_pos, 30, option.description[:width-32], curses.color_pair(4))
            else:
                self.screen.addstr(y_pos, 2, f"  {option.name}")
    
    def draw_stats_panel(self, start_y, width):
        """Draw the statistics panel."""
        panel_start_y = start_y + len(self.menus[self.current_menu]) + 5
        
        self.screen.addstr(panel_start_y, 2, "Statistics", curses.A_BOLD)
        self.screen.addstr(panel_start_y + 1, 2, "-" * 10)
        
        # Draw stats
        stats_y = panel_start_y + 2
        
        # Scanning status indicators
        proxy_status = "ACTIVE" if self.proxy_scanning_active else "INACTIVE"
        amp_status = "ACTIVE" if self.amp_scanning_active else "INACTIVE"
        
        proxy_color = curses.color_pair(1) if self.proxy_scanning_active else curses.color_pair(2)
        amp_color = curses.color_pair(1) if self.amp_scanning_active else curses.color_pair(2)
        
        self.screen.addstr(stats_y, 2, f"Proxy Scanning: ")
        self.screen.addstr(proxy_status, proxy_color)
        
        self.screen.addstr(stats_y + 1, 2, f"Amplification Scanning: ")
        self.screen.addstr(amp_status, amp_color)
        
        self.screen.addstr(stats_y + 3, 2, f"Proxies: {self.stats['proxies_working']}/{self.stats['proxies_total']}")
        self.screen.addstr(stats_y + 4, 2, f"Amplification Servers: {self.stats['amp_servers_working']}/{self.stats['amp_servers_total']}")
        self.screen.addstr(stats_y + 5, 2, f"Running Attacks: {self.stats['attacks_running']}")
        self.screen.addstr(stats_y + 6, 2, f"Scan Threads (Proxy/Amp): {self.stats['scan_threads_proxy']}/{self.stats['scan_threads_amp']}")
        
        # Draw checkboxes status
        checkbox_y = stats_y + 8
        self.screen.addstr(checkbox_y, 2, "Settings:", curses.A_BOLD)
        
        for i, (key, checkbox) in enumerate(self.checkboxes.items()):
            status = "[X]" if checkbox.checked else "[ ]"
            status_color = curses.color_pair(1) if checkbox.checked else curses.color_pair(2)
            
            self.screen.addstr(checkbox_y + 1 + i, 2, f"{checkbox.name}: ")
            self.screen.addstr(status, status_color)
    
    def draw_status_bar(self, y, width):
        """Draw the status bar at the bottom of the screen."""
        self.screen.addstr(y, 0, "=" * (width - 1))
        
        # Display status message with appropriate color
        if self.status_message:
            self.screen.addstr(y + 1, 2, self.status_message[:width-4], 
                              curses.color_pair(self.status_color))
        else:
            self.screen.addstr(y + 1, 2, "Ready", curses.color_pair(1))
    
    def handle_input(self):
        """Handle user input."""
        key = self.screen.getch()
        
        if key == curses.KEY_UP:
            self.selected_index = max(0, self.selected_index - 1)
        elif key == curses.KEY_DOWN:
            self.selected_index = min(len(self.menus[self.current_menu]) - 1, self.selected_index + 1)
        elif key == curses.KEY_ENTER or key == 10 or key == 13:
            # Execute the selected option's callback
            if 0 <= self.selected_index < len(self.menus[self.current_menu]):
                self.menus[self.current_menu][self.selected_index].callback()
        elif key == 27:  # ESC key
            if self.current_menu != "main":
                self.change_menu("main")
            else:
                self.show_quit_confirmation()
    
    def change_menu(self, menu_name):
        """Change the current menu."""
        if menu_name in self.menus:
            self.current_menu = menu_name
            self.selected_index = 0
            self.set_status(f"Switched to {menu_name} menu", 4)
    
    def set_status(self, message, color=0):
        """Set the status message with a color."""
        self.status_message = message
        self.status_color = color
    
    def update_stats_thread(self):
        """Background thread to update statistics."""
        while self.running:
            try:
                # Update proxy stats
                proxies = self.storage.get_all_proxies()
                working_proxies = [p for p in proxies if p.get("working", False)]
                
                self.stats["proxies_total"] = len(proxies)
                self.stats["proxies_working"] = len(working_proxies)
                
                # Update amplification server stats
                amp_servers = self.storage.get_all_amplification_servers()
                working_servers = [s for s in amp_servers if s.get("working", False)]
                
                self.stats["amp_servers_total"] = len(amp_servers)
                self.stats["amp_servers_working"] = len(working_servers)
                
                # Update thread counts
                self.stats["scan_threads_proxy"] = self.proxy_scanner.get_thread_count()
                self.stats["scan_threads_amp"] = self.amp_scanner.get_thread_count()
                
                # Update attacks count
                self.stats["attacks_running"] = (
                    self.layer4.get_running_attacks_count() + 
                    self.layer7.get_running_attacks_count()
                )
                
                time.sleep(1)  # Update once per second
            except Exception as e:
                logger.error(f"Error updating stats: {e}")
                time.sleep(5)  # Wait longer on error
    
    # Menu callbacks
    def toggle_proxy_scanning(self):
        """Toggle proxy scanning on/off."""
        self.proxy_scanning_active = not self.proxy_scanning_active
        
        if self.proxy_scanning_active:
            self.proxy_scanner.start_scanning()
            self.set_status("Proxy scanning started", 1)
        else:
            self.proxy_scanner.stop_scanning()
            self.set_status("Proxy scanning stopped", 3)
    
    def toggle_amp_scanning(self):
        """Toggle amplification server scanning on/off."""
        self.amp_scanning_active = not self.amp_scanning_active
        
        if self.amp_scanning_active:
            self.amp_scanner.start_scanning()
            self.set_status("Amplification server scanning started", 1)
        else:
            self.amp_scanner.stop_scanning()
            self.set_status("Amplification server scanning stopped", 3)
    
    def test_existing_proxies(self):
        """Test all existing proxies."""
        proxy_count = self.storage.get_proxy_count()
        if proxy_count == 0:
            self.set_status("No proxies to test", 3)
            return
        
        self.set_status(f"Testing {proxy_count} proxies...", 4)
        threading.Thread(target=self._test_proxies_thread, daemon=True).start()
    
    def _test_proxies_thread(self):
        """Background thread for testing proxies."""
        try:
            self.proxy_scanner.test_all_proxies()
            self.set_status("Proxy testing completed", 1)
        except Exception as e:
            self.set_status(f"Error testing proxies: {e}", 2)
    
    def test_existing_amps(self):
        """Test all existing amplification servers."""
        server_count = self.storage.get_amplification_server_count()
        if server_count == 0:
            self.set_status("No amplification servers to test", 3)
            return
        
        self.set_status(f"Testing {server_count} amplification servers...", 4)
        threading.Thread(target=self._test_amps_thread, daemon=True).start()
    
    def _test_amps_thread(self):
        """Background thread for testing amplification servers."""
        try:
            self.amp_scanner.test_all_servers()
            self.set_status("Amplification server testing completed", 1)
        except Exception as e:
            self.set_status(f"Error testing amplification servers: {e}", 2)
    
    def view_proxies(self):
        """View discovered proxies."""
        # This would open a new window showing proxies
        # For simplicity, we'll just display a count in the status bar
        proxy_count = self.storage.get_proxy_count()
        if proxy_count == 0:
            self.set_status("No proxies available", 3)
        else:
            self.set_status(f"Found {proxy_count} proxies. Feature to view details coming soon.", 4)
    
    def view_amp_servers(self):
        """View discovered amplification servers."""
        server_count = self.storage.get_amplification_server_count()
        if server_count == 0:
            self.set_status("No amplification servers available", 3)
        else:
            self.set_status(f"Found {server_count} amplification servers. Feature to view details coming soon.", 4)
    
    def import_proxies(self):
        """Import proxies from file."""
        self.set_status("Import feature not implemented yet", 3)
    
    def export_proxies(self):
        """Export proxies to file."""
        self.set_status("Export feature not implemented yet", 3)
    
    def clear_proxies(self):
        """Clear all proxies."""
        self.storage.clear_proxies()
        self.set_status("All proxies cleared", 3)
    
    def import_amp_servers(self):
        """Import amplification servers from file."""
        self.set_status("Import feature not implemented yet", 3)
    
    def export_amp_servers(self):
        """Export amplification servers to file."""
        self.set_status("Export feature not implemented yet", 3)
    
    def clear_amp_servers(self):
        """Clear all amplification servers."""
        self.storage.clear_amplification_servers()
        self.set_status("All amplification servers cleared", 3)
    
    def start_attack(self, attack_type):
        """Start a network security test."""
        if not self.checkboxes["ethical_mode"].checked:
            self.set_status("Cannot start attack: Ethical mode is disabled", 2)
            return
        
        # For the UI demo, just show a status message
        self.set_status(f"Starting {attack_type} test (this would open an attack configuration screen)", 4)
        
        # In a full implementation, this would open a dialog to configure attack parameters
        # and then launch the actual attack
    
    def stop_all_attacks(self):
        """Stop all running attacks."""
        self.layer4.stop_all_attacks()
        self.layer7.stop_all_attacks()
        self.set_status("All attacks stopped", 3)
    
    def toggle_checkbox(self, checkbox_name):
        """Toggle a checkbox setting."""
        if checkbox_name in self.checkboxes:
            self.checkboxes[checkbox_name].checked = not self.checkboxes[checkbox_name].checked
            status = "enabled" if self.checkboxes[checkbox_name].checked else "disabled"
            self.set_status(f"{self.checkboxes[checkbox_name].name} {status}", 4)
    
    def configure_threads(self):
        """Configure thread counts for various operations."""
        self.set_status("Thread configuration feature not implemented yet", 3)
    
    def show_proxy_menu(self):
        """Show the proxy management menu."""
        self.change_menu("proxy")
    
    def show_amp_menu(self):
        """Show the amplification server management menu."""
        self.change_menu("amplification")
    
    def show_layer4_menu(self):
        """Show the Layer 4 testing menu."""
        self.change_menu("layer4")
    
    def show_layer7_menu(self):
        """Show the Layer 7 testing menu."""
        self.change_menu("layer7")
    
    def show_settings_menu(self):
        """Show the settings menu."""
        self.change_menu("settings")
    
    def show_quit_confirmation(self):
        """Show quit confirmation dialog."""
        self.set_status("Press 'q' to confirm exit, any other key to cancel", 3)
        key = self.screen.getch()
        if key == ord('q') or key == ord('Q'):
            self.quit()
        else:
            self.set_status("Exit cancelled", 4)
    
    def quit(self):
        """Exit the application."""
        self.running = False
        self.proxy_scanner.stop_scanning()
        self.amp_scanner.stop_scanning()
        self.layer4.stop_all_attacks()
        self.layer7.stop_all_attacks()
