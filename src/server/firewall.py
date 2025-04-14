
#!/usr/bin/env python3
"""
Piso WiFi Fortress - Firewall Management Script

This script provides utilities for managing the system firewall rules
to control client access to the WiFi network.

For Linux systems, it uses iptables.
For Windows systems, it uses Windows Firewall via netsh.

Features:
- Whitelist MAC/IP pairs for authenticated clients
- Block suspicious or abusive clients
- Clean up expired rules
- Apply port/protocol restrictions

Usage:
  python firewall.py whitelist <mac> <ip>  # Allow access for client
  python firewall.py block <mac> <ip>      # Block access for client
  python firewall.py clean                 # Clean up expired rules
  python firewall.py status                # Show current rules
"""

import os
import sys
import subprocess
import argparse
import re
import json
import logging
import time
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("firewall.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("wifi_firewall")

# Constants
IS_WINDOWS = os.name == 'nt'
RULE_PREFIX = "WiFiFortress"
CONFIG_FILE = "firewall_rules.json"

# Define blocked ports (common VPN and tunneling ports)
BLOCKED_PORTS_TCP = [
    22,     # SSH
    1194,   # OpenVPN
    1701,   # L2TP
    1723,   # PPTP
    4500,   # IPSec NAT-T
    8080,   # HTTP Proxy
    8443,   # HTTPS Proxy
    10000,  # VPN
]

BLOCKED_PORTS_UDP = [
    53,     # DNS (to prevent DNS tunneling - clients must use our DNS)
    500,    # IKE for IPSec
    1194,   # OpenVPN
    1701,   # L2TP
    4500,   # IPSec NAT-T
]

def validate_mac(mac):
    """Validate MAC address format"""
    pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return bool(pattern.match(mac))

def validate_ip(ip):
    """Validate IP address format"""
    pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not pattern.match(ip):
        return False
    
    # Check each octet is in range 0-255
    for octet in ip.split('.'):
        if not 0 <= int(octet) <= 255:
            return False
    return True

def load_rules():
    """Load stored firewall rules from JSON file"""
    if not os.path.exists(CONFIG_FILE):
        return {"whitelisted": {}, "blocked": {}}
    
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Error loading rules: {e}")
        return {"whitelisted": {}, "blocked": {}}

def save_rules(rules):
    """Save firewall rules to JSON file"""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(rules, f, indent=2)
    except IOError as e:
        logger.error(f"Error saving rules: {e}")

def run_command(command):
    """Run a shell command and return the output"""
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e}")
        logger.error(f"Error output: {e.stderr}")
        return None

def whitelist_client(mac, ip):
    """Allow internet access for a specific client by MAC and IP"""
    if not validate_mac(mac):
        logger.error(f"Invalid MAC address: {mac}")
        return False
    
    if not validate_ip(ip):
        logger.error(f"Invalid IP address: {ip}")
        return False
    
    rules = load_rules()
    
    # Remove from blocked list if present
    if mac in rules["blocked"]:
        del rules["blocked"][mac]
    
    # Add to whitelist with timestamp
    rules["whitelisted"][mac] = {
        "ip": ip,
        "added": datetime.now().isoformat()
    }
    
    # Apply the firewall rules
    success = False
    
    if IS_WINDOWS:
        # Windows Firewall
        rule_name = f"{RULE_PREFIX}-Allow-{mac.replace(':', '')}"
        
        # First, remove any existing rule with this name
        run_command([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}"
        ])
        
        # Add new allow rule
        result = run_command([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=allow",
            f"remoteip={ip}"
        ])
        
        success = result is not None
    else:
        # Linux iptables
        # First, clear any existing rules for this MAC/IP
        run_command(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
        run_command(["iptables", "-D", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP"])
        
        # Add whitelist rules
        cmd1 = run_command([
            "iptables", "-A", "FORWARD", "-s", ip, "-m", "mac",
            "--mac-source", mac, "-j", "ACCEPT"
        ])
        
        cmd2 = run_command([
            "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", ip,
            "-j", "MASQUERADE"
        ])
        
        # Block specific ports/protocols
        for port in BLOCKED_PORTS_TCP:
            run_command([
                "iptables", "-A", "FORWARD", "-s", ip, "-p", "tcp", 
                "--dport", str(port), "-j", "DROP"
            ])
            
        for port in BLOCKED_PORTS_UDP:
            run_command([
                "iptables", "-A", "FORWARD", "-s", ip, "-p", "udp", 
                "--dport", str(port), "-j", "DROP"
            ])
        
        success = cmd1 is not None and cmd2 is not None
    
    # Save rules if successful
    if success:
        save_rules(rules)
        logger.info(f"Whitelisted client: MAC={mac}, IP={ip}")
    else:
        logger.error(f"Failed to whitelist client: MAC={mac}, IP={ip}")
    
    return success

def block_client(mac, ip):
    """Block internet access for a specific client"""
    if not validate_mac(mac) and not validate_ip(ip):
        logger.error(f"Invalid MAC ({mac}) or IP ({ip})")
        return False
    
    rules = load_rules()
    
    # Remove from whitelist if present
    if mac in rules["whitelisted"]:
        del rules["whitelisted"][mac]
    
    # Add to blocked list with timestamp
    rules["blocked"][mac] = {
        "ip": ip,
        "added": datetime.now().isoformat()
    }
    
    # Apply the firewall rules
    success = False
    
    if IS_WINDOWS:
        # Windows Firewall
        rule_name = f"{RULE_PREFIX}-Block-{mac.replace(':', '')}"
        
        # First, remove any existing rule with this name
        run_command([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}"
        ])
        
        # Add new block rule
        result = run_command([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip}"
        ])
        
        success = result is not None
    else:
        # Linux iptables
        # First, clear any existing whitelist rules
        run_command([
            "iptables", "-D", "FORWARD", "-s", ip, "-m", "mac",
            "--mac-source", mac, "-j", "ACCEPT"
        ])
        run_command([
            "iptables", "-t", "nat", "-D", "POSTROUTING", "-s", ip,
            "-j", "MASQUERADE"
        ])
        
        # Add block rules
        cmd1 = None
        cmd2 = None
        
        if validate_ip(ip):
            cmd1 = run_command([
                "iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"
            ])
        
        if validate_mac(mac):
            cmd2 = run_command([
                "iptables", "-A", "FORWARD", "-m", "mac", "--mac-source", mac,
                "-j", "DROP"
            ])
        
        success = (cmd1 is not None) or (cmd2 is not None)
    
    # Save rules if successful
    if success:
        save_rules(rules)
        logger.info(f"Blocked client: MAC={mac}, IP={ip}")
    else:
        logger.error(f"Failed to block client: MAC={mac}, IP={ip}")
    
    return success

def clean_rules():
    """Clean up expired or inconsistent rules"""
    rules = load_rules()
    cleaned = 0
    
    # Cleanup logic would go here, for example:
    # - Remove rules older than a certain time
    # - Ensure all stored rules have corresponding firewall entries
    # - Remove duplicate or conflicting rules
    
    logger.info(f"Cleaned {cleaned} rules")
    return True

def show_status():
    """Display current firewall rules status"""
    rules = load_rules()
    
    print("\n=== Piso WiFi Fortress Firewall Status ===\n")
    
    print("Whitelisted Clients:")
    if rules["whitelisted"]:
        for mac, data in rules["whitelisted"].items():
            print(f"  MAC: {mac}")
            print(f"  IP: {data['ip']}")
            print(f"  Added: {data['added']}")
            print("")
    else:
        print("  No whitelisted clients")
    
    print("\nBlocked Clients:")
    if rules["blocked"]:
        for mac, data in rules["blocked"].items():
            print(f"  MAC: {mac}")
            print(f"  IP: {data['ip']}")
            print(f"  Added: {data['added']}")
            print("")
    else:
        print("  No blocked clients")
    
    # Show actual firewall rules
    print("\nSystem Firewall Rules:")
    if IS_WINDOWS:
        # Windows Firewall
        result = run_command([
            "netsh", "advfirewall", "firewall", "show", "rule", 
            f"name={RULE_PREFIX}*"
        ])
        print(result or "  No rules found")
    else:
        # Linux iptables
        forward_rules = run_command(["iptables", "-L", "FORWARD", "-n", "-v"])
        nat_rules = run_command(["iptables", "-t", "nat", "-L", "POSTROUTING", "-n", "-v"])
        
        print("FORWARD Chain:")
        print(forward_rules or "  No rules found")
        print("\nPOSTROUTING Chain (NAT):")
        print(nat_rules or "  No rules found")

def main():
    parser = argparse.ArgumentParser(description="Piso WiFi Fortress Firewall Manager")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Whitelist command
    whitelist_parser = subparsers.add_parser("whitelist", help="Allow access for a client")
    whitelist_parser.add_argument("mac", help="MAC address (format: XX:XX:XX:XX:XX:XX)")
    whitelist_parser.add_argument("ip", help="IP address (format: XXX.XXX.XXX.XXX)")
    
    # Block command
    block_parser = subparsers.add_parser("block", help="Block access for a client")
    block_parser.add_argument("mac", help="MAC address (format: XX:XX:XX:XX:XX:XX)")
    block_parser.add_argument("ip", help="IP address (format: XXX.XXX.XXX.XXX)")
    
    # Clean command
    subparsers.add_parser("clean", help="Clean up expired and inconsistent rules")
    
    # Status command
    subparsers.add_parser("status", help="Show current firewall rules")
    
    args = parser.parse_args()
    
    # Check for root/admin privileges
    if os.geteuid() != 0 and not IS_WINDOWS:
        print("Error: This script must be run as root")
        sys.exit(1)
    
    # Execute command
    if args.command == "whitelist":
        if whitelist_client(args.mac, args.ip):
            print(f"Client {args.mac} ({args.ip}) whitelisted successfully")
        else:
            print(f"Failed to whitelist client {args.mac} ({args.ip})")
            sys.exit(1)
    
    elif args.command == "block":
        if block_client(args.mac, args.ip):
            print(f"Client {args.mac} ({args.ip}) blocked successfully")
        else:
            print(f"Failed to block client {args.mac} ({args.ip})")
            sys.exit(1)
    
    elif args.command == "clean":
        if clean_rules():
            print("Rules cleaned successfully")
        else:
            print("Failed to clean rules")
            sys.exit(1)
    
    elif args.command == "status":
        show_status()
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
