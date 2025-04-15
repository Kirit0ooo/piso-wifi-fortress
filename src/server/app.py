
"""
Piso WiFi Fortress - Flask Backend Server

This is a Flask application that powers the backend of the Piso WiFi Fortress system.
It provides APIs for voucher validation, coin slot integration, and session management.

Security Features:
- MAC + IP binding for all sessions
- Token-based authentication
- Rate limiting on critical endpoints
- Firewall integration via iptables/netsh
- Comprehensive logging
- Protection against common attacks

NOTE: This is a template/example. In a production system:
1. Use HTTPS with proper certificates
2. Store secrets securely (not in code)
3. Implement proper database storage
4. Add more comprehensive error handling
"""

import os
import time
import uuid
import json
import sqlite3
import ipaddress
import subprocess
import logging
import hashlib
import hmac
import secrets
import random
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, 
    request, 
    jsonify, 
    render_template, 
    redirect, 
    url_for, 
    session
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("wifi_fortress.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("wifi_fortress")

# Initialize Flask application
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # In production, load from environment variable

# Rate limiting configuration
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Configuration
DATABASE_PATH = "users.db"
ADMIN_USERNAME = "admin"  # In production, load from environment variable
ADMIN_PASSWORD_HASH = generate_password_hash("admin_password")  # In production, load from environment variable
API_KEY = "YOUR_API_KEY"  # In production, load from environment variable
COIN_RATE = 5  # PHP 5 per 25 minutes
WHITELIST_TIMEOUT = 30  # 30 seconds to whitelist after auth
IS_WINDOWS = os.name == 'nt'
MAX_PAUSE_COUNT = 3  # Maximum number of times a user can pause their session
MIN_PAUSE_INTERVAL = 10 * 60  # 10 minutes in seconds
PAUSE_EXPIRY = 24  # Paused sessions expire after 24 hours

# Known ESP8266 devices (in production, load from secure storage)
KNOWN_DEVICES = {
    "COIN-ESP-001": {
        "name": "Main Entrance Coin Slot",
        "secret": "device_secret_key_1"
    },
    "COIN-ESP-002": {
        "name": "Side Entrance Coin Slot",
        "secret": "device_secret_key_2"
    }
}

# Database initialization
def init_db():
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        # Create tables if they don't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vouchers (
                id TEXT PRIMARY KEY,
                code TEXT UNIQUE NOT NULL,
                minutes INTEGER NOT NULL,
                is_used BOOLEAN DEFAULT 0,
                used_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used_at TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                mac_address TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                token TEXT NOT NULL,
                auth_method TEXT NOT NULL,
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIMESTAMP NOT NULL,
                total_minutes INTEGER NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                is_paused BOOLEAN DEFAULT 0,
                paused_at TIMESTAMP,
                pause_expires_at TIMESTAMP,
                remaining_seconds INTEGER,
                pause_count INTEGER DEFAULT 0,
                last_pause_time TIMESTAMP,
                data_used INTEGER DEFAULT 0
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_clients (
                mac_address TEXT PRIMARY KEY,
                ip_address TEXT,
                reason TEXT NOT NULL,
                blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expire_at TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                description TEXT NOT NULL,
                client_mac TEXT,
                client_ip TEXT,
                details TEXT
            )
        ''')
        # Create some sample vouchers
        sample_vouchers = [
            ("FREE123", 60),  # 60 minutes
            ("TEST456", 120),  # 120 minutes
        ]
        for code, minutes in sample_vouchers:
            try:
                cursor.execute(
                    "INSERT INTO vouchers (id, code, minutes) VALUES (?, ?, ?)",
                    (str(uuid.uuid4()), code, minutes)
                )
            except sqlite3.IntegrityError:
                # Voucher already exists
                pass
        conn.commit()

# Initialize database at startup
init_db()

# Security decorators and helpers
# ... keep existing code (security decorators and helpers)

def get_client_mac():
    """Get client MAC address from various headers or ARP table"""
    # Try to get from custom header if set by gateway
    mac = request.headers.get('X-Client-MAC')
    
    if not mac:
        # In production, you would implement proper MAC detection
        # This could involve checking the ARP table using the client IP
        client_ip = get_client_ip()
        if IS_WINDOWS:
            try:
                # On Windows, use arp -a
                result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
                lines = result.stdout.splitlines()
                for line in lines:
                    if client_ip in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            mac = parts[1].replace('-', ':')
                            break
            except Exception as e:
                logger.error(f"Error getting MAC from ARP: {e}")
        else:
            try:
                # On Linux, check /proc/net/arp
                with open('/proc/net/arp', 'r') as f:
                    lines = f.readlines()[1:]  # Skip header
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 6 and parts[0] == client_ip:
                            mac = parts[3]
                            break
            except Exception as e:
                logger.error(f"Error getting MAC from ARP: {e}")
    
    # If we still don't have a MAC, generate a fake one for demo
    # In production, you should handle this case differently
    if not mac:
        mac = "AA:BB:CC:DD:EE:FF"  # Placeholder for demo
        
    return mac.upper()

def get_client_ip():
    """Get client's real IP address accounting for proxies"""
    if request.headers.get('X-Forwarded-For'):
        # If behind a proxy, get the real client IP
        client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        client_ip = request.remote_addr
    return client_ip

# ... keep existing code (validation functions)

def validate_mac_address(mac):
    """Validate MAC address format"""
    import re
    pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return bool(pattern.match(mac))

def check_duplicate_mac(mac):
    """Check if this MAC is suspected of being duplicated/spoofed"""
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        # Look for active sessions with this MAC but different IPs
        cursor.execute('''
            SELECT COUNT(*) FROM sessions 
            WHERE mac_address = ? 
            AND is_active = 1 
            AND ip_address != ?
        ''', (mac, get_client_ip()))
        count = cursor.fetchone()[0]
        if count > 0:
            return True
            
        # Check for rapid session changes (possible MAC spoofing)
        one_hour_ago = datetime.now() - timedelta(hours=1)
        cursor.execute('''
            SELECT COUNT(*) FROM sessions 
            WHERE mac_address = ? 
            AND start_time > ?
        ''', (mac, one_hour_ago))
        recent_sessions = cursor.fetchone()[0]
        if recent_sessions > 5:  # More than 5 sessions in the last hour is suspicious
            return True
            
    return False

def is_client_blocked(mac=None, ip=None):
    """Check if client is on the blocklist"""
    if not mac:
        mac = get_client_mac()
    if not ip:
        ip = get_client_ip()
        
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        now = datetime.now()
        cursor.execute('''
            SELECT COUNT(*) FROM blocked_clients 
            WHERE (mac_address = ? OR ip_address = ?) 
            AND (expire_at IS NULL OR expire_at > ?)
        ''', (mac, ip, now))
        count = cursor.fetchone()[0]
        return count > 0

def block_client(mac, ip, reason, duration_hours=24):
    """Add client to blocklist"""
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        expire_at = datetime.now() + timedelta(hours=duration_hours)
        cursor.execute('''
            INSERT INTO blocked_clients (mac_address, ip_address, reason, expire_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(mac_address) DO UPDATE SET
                ip_address=excluded.ip_address,
                reason=excluded.reason,
                blocked_at=CURRENT_TIMESTAMP,
                expire_at=excluded.expire_at
        ''', (mac, ip, reason, expire_at))
        conn.commit()
    
    # Also block at firewall level
    apply_firewall_block(mac, ip)
    log_security_event(f"Client blocked: {reason}", client_mac=mac, client_ip=ip)

# ... keep existing code (firewall functions)

def apply_firewall_whitelist(mac, ip):
    """Apply firewall rules to allow client access"""
    try:
        if IS_WINDOWS:
            # Windows firewall commands (netsh)
            rule_name = f"WiFiFortress-Allow-{mac.replace(':', '')}"
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", 
                           f"name={rule_name}", "dir=in", "action=allow", 
                           f"remoteip={ip}"], check=True)
        else:
            # Linux iptables commands
            subprocess.run(["iptables", "-A", "FORWARD", "-s", ip, "-m", "mac", 
                           "--mac-source", mac, "-j", "ACCEPT"], check=True)
            subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", ip, 
                           "-j", "MASQUERADE"], check=True)
    except subprocess.SubprocessError as e:
        logger.error(f"Firewall whitelist error: {e}")
        return False
    return True

def apply_firewall_block(mac, ip):
    """Apply firewall rules to block client access"""
    try:
        if IS_WINDOWS:
            # Windows firewall commands (netsh)
            rule_name = f"WiFiFortress-Block-{mac.replace(':', '')}"
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", 
                           f"name={rule_name}", "dir=in", "action=block", 
                           f"remoteip={ip}"], check=True)
        else:
            # Linux iptables commands
            subprocess.run(["iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"], check=True)
            subprocess.run(["iptables", "-A", "FORWARD", "-m", "mac", "--mac-source", mac, 
                           "-j", "DROP"], check=True)
    except subprocess.SubprocessError as e:
        logger.error(f"Firewall block error: {e}")
        return False
    return True

def remove_firewall_rules(mac, ip):
    """Remove client firewall rules"""
    try:
        if IS_WINDOWS:
            # Windows firewall commands (netsh)
            allow_rule = f"WiFiFortress-Allow-{mac.replace(':', '')}"
            block_rule = f"WiFiFortress-Block-{mac.replace(':', '')}"
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", 
                           f"name={allow_rule}"], check=True)
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", 
                           f"name={block_rule}"], check=True)
        else:
            # Linux iptables commands
            subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-m", "mac", 
                           "--mac-source", mac, "-j", "ACCEPT"], check=True)
            subprocess.run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", ip, 
                           "-j", "MASQUERADE"], check=True)
            subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], check=True)
            subprocess.run(["iptables", "-D", "FORWARD", "-m", "mac", "--mac-source", mac, 
                           "-j", "DROP"], check=True)
    except subprocess.SubprocessError as e:
        logger.error(f"Firewall rule removal error: {e}")
        return False
    return True

def create_session(mac_address, ip_address, minutes, auth_method):
    """Create a new user session"""
    session_id = str(uuid.uuid4())
    token = secrets.token_urlsafe(32)
    start_time = datetime.now()
    end_time = start_time + timedelta(minutes=minutes)
    
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        
        # First, terminate any existing sessions for this MAC/IP
        cursor.execute('''
            UPDATE sessions SET is_active = 0 
            WHERE (mac_address = ? OR ip_address = ?) AND is_active = 1
        ''', (mac_address, ip_address))
        
        # Create new session
        cursor.execute('''
            INSERT INTO sessions 
            (id, mac_address, ip_address, token, auth_method, start_time, end_time, total_minutes, is_active, pause_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0)
        ''', (session_id, mac_address, ip_address, token, auth_method, start_time, end_time, minutes))
        conn.commit()
        
    # Apply firewall rules
    apply_firewall_whitelist(mac_address, ip_address)
    
    log_event(f"New session created via {auth_method}", client_mac=mac_address, client_ip=ip_address,
              details=json.dumps({"minutes": minutes, "session_id": session_id}))
              
    return {"session_id": session_id, "token": token, "expires": end_time.isoformat()}

def validate_session(token):
    """Validate a session token"""
    if not token:
        return None
        
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, mac_address, ip_address, end_time, is_paused, remaining_seconds 
            FROM sessions 
            WHERE token = ? AND is_active = 1
        ''', (token,))
        result = cursor.fetchone()
        
        if not result:
            return None
            
        session_id, mac, ip, end_time_str, is_paused, remaining_seconds = result
        
        # If session is not paused, check expiration
        if is_paused == 0:
            end_time = datetime.fromisoformat(end_time_str)
            
            # Check if session expired
            if datetime.now() > end_time:
                # Session expired
                cursor.execute('UPDATE sessions SET is_active = 0 WHERE id = ?', (session_id,))
                conn.commit()
                return None
        
        # Check MAC and IP match  
        client_mac = get_client_mac()
        client_ip = get_client_ip()
        
        if client_mac != mac or client_ip != ip:
            log_security_event("Session binding mismatch", 
                             client_mac=client_mac, client_ip=client_ip,
                             details=f"Expected MAC: {mac}, IP: {ip}")
            return None
            
    return {
        "session_id": session_id, 
        "mac": mac, 
        "ip": ip, 
        "end_time": end_time_str,
        "is_paused": bool(is_paused),
        "remaining_seconds": remaining_seconds
    }

def get_paused_session(mac=None, ip=None):
    """Check if a client has a paused session"""
    if not mac:
        mac = get_client_mac()
    if not ip:
        ip = get_client_ip()
        
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, token, auth_method, remaining_seconds, paused_at, pause_expires_at
            FROM sessions 
            WHERE mac_address = ? AND ip_address = ? AND is_active = 1 AND is_paused = 1
            ORDER BY paused_at DESC
            LIMIT 1
        ''', (mac, ip))
        
        result = cursor.fetchone()
        if not result:
            return None
            
        session_id, token, auth_method, remaining_seconds, paused_at, pause_expires_at = result
        
        # Check if pause expired
        if pause_expires_at:
            expiry_time = datetime.fromisoformat(pause_expires_at)
            if datetime.now() > expiry_time:
                # Pause expired, end session
                cursor.execute('UPDATE sessions SET is_active = 0 WHERE id = ?', (session_id,))
                conn.commit()
                
                log_event("Paused session expired", client_mac=mac, client_ip=ip, 
                         details=session_id)
                return None
        
        # Calculate remaining human-readable time
        hours = remaining_seconds // 3600
        minutes = (remaining_seconds % 3600) // 60
        seconds = remaining_seconds % 60
        time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        
        return {
            "session_id": session_id,
            "token": token,
            "auth_method": auth_method,
            "remaining_seconds": remaining_seconds,
            "remaining_time": time_str,
            "paused_at": paused_at,
            "pause_expires_at": pause_expires_at
        }

def pause_session(session_id, mac, ip):
    """Pause an active session"""
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        
        # Check pause count and interval limitations
        cursor.execute('''
            SELECT pause_count, last_pause_time, start_time, end_time
            FROM sessions
            WHERE id = ? AND is_active = 1 AND is_paused = 0
        ''', (session_id,))
        
        result = cursor.fetchone()
        if not result:
            return False, "Session not found or already paused"
            
        pause_count, last_pause_time, start_time, end_time = result
        
        # Check if max pause count reached
        if pause_count >= MAX_PAUSE_COUNT:
            return False, f"Maximum pause limit ({MAX_PAUSE_COUNT}) reached"
        
        # Check minimum pause interval if not first pause
        now = datetime.now()
        if last_pause_time and pause_count > 0:
            last_pause = datetime.fromisoformat(last_pause_time)
            seconds_since_last_pause = (now - last_pause).total_seconds()
            
            if seconds_since_last_pause < MIN_PAUSE_INTERVAL:
                minutes_to_wait = (MIN_PAUSE_INTERVAL - seconds_since_last_pause) // 60
                return False, f"Please wait {int(minutes_to_wait)} more minute(s) before pausing again"
        
        # Calculate remaining time
        end_time = datetime.fromisoformat(end_time)
        remaining_seconds = max(0, int((end_time - now).total_seconds()))
        
        # Set pause expiration time
        pause_expires_at = now + timedelta(hours=PAUSE_EXPIRY)
        
        # Update session to paused state
        cursor.execute('''
            UPDATE sessions 
            SET is_paused = 1, 
                paused_at = ?, 
                pause_expires_at = ?,
                remaining_seconds = ?,
                pause_count = pause_count + 1,
                last_pause_time = ?
            WHERE id = ?
        ''', (now, pause_expires_at, remaining_seconds, now, session_id))
        conn.commit()
    
    # Block internet access
    apply_firewall_block(mac, ip)
    
    log_event("Session paused", client_mac=mac, client_ip=ip, 
             details=f"Session {session_id} paused with {remaining_seconds} seconds remaining")
             
    return True, "Session paused successfully"

def resume_session(session_id, mac, ip):
    """Resume a paused session"""
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        
        # Get session data
        cursor.execute('''
            SELECT remaining_seconds
            FROM sessions
            WHERE id = ? AND is_active = 1 AND is_paused = 1
        ''', (session_id,))
        
        result = cursor.fetchone()
        if not result:
            return False, "No paused session found"
            
        remaining_seconds = result[0]
        
        # Calculate new end time
        now = datetime.now()
        new_end_time = now + timedelta(seconds=remaining_seconds)
        
        # Update session to active state
        cursor.execute('''
            UPDATE sessions 
            SET is_paused = 0, 
                paused_at = NULL, 
                pause_expires_at = NULL,
                end_time = ?
            WHERE id = ?
        ''', (new_end_time, session_id))
        conn.commit()
    
    # Allow internet access again
    remove_firewall_rules(mac, ip)  # Remove any existing rules
    apply_firewall_whitelist(mac, ip)  # Apply whitelist rules
    
    log_event("Session resumed", client_mac=mac, client_ip=ip, 
             details=f"Session {session_id} resumed with {remaining_seconds} seconds remaining")
             
    return True, "Session resumed successfully"

def end_session(session_id):
    """End a user session"""
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT mac_address, ip_address FROM sessions WHERE id = ?', (session_id,))
        result = cursor.fetchone()
        
        if result:
            mac, ip = result
            cursor.execute('UPDATE sessions SET is_active = 0 WHERE id = ?', (session_id,))
            conn.commit()
            
            # Remove firewall rules
            remove_firewall_rules(mac, ip)
            log_event("Session ended", client_mac=mac, client_ip=ip, details=session_id)
            return True
    return False

# ... keep existing code (logging functions)

def log_event(event_type, description=None, client_mac=None, client_ip=None, details=None):
    """Log an event to the database"""
    if not description:
        description = event_type
        
    if not client_mac:
        client_mac = get_client_mac()
        
    if not client_ip:
        client_ip = get_client_ip()
        
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO logs (event_type, description, client_mac, client_ip, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (event_type, description, client_mac, client_ip, details))
        conn.commit()
        
    logger.info(f"{event_type}: {description} | MAC: {client_mac} | IP: {client_ip}")

def log_security_event(description, client_mac=None, client_ip=None, details=None):
    """Log a security-related event"""
    log_event("SECURITY", description, client_mac, client_ip, details)
    logger.warning(f"SECURITY ALERT: {description} | MAC: {client_mac or 'Unknown'} | IP: {client_ip or 'Unknown'}")

# Run maintenance tasks on a schedule (this would typically be in a separate thread or process)
def maintenance_tasks():
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        now = datetime.now()
        
        # Deactivate expired sessions
        cursor.execute('''
            UPDATE sessions SET is_active = 0 
            WHERE is_active = 1 AND is_paused = 0 AND end_time < ?
        ''', (now,))
        
        # Deactivate expired pauses
        cursor.execute('''
            UPDATE sessions SET is_active = 0 
            WHERE is_active = 1 AND is_paused = 1 AND pause_expires_at < ?
        ''', (now,))
        
        # Remove expired blocks
        cursor.execute('DELETE FROM blocked_clients WHERE expire_at < ?', (now,))
        
        conn.commit()
        
# Routes and API endpoints

@app.route('/')
def index():
    """Captive portal main page"""
    # Check if this is a captive portal detection request
    user_agent = request.headers.get('User-Agent', '').lower()
    if 'captiveportal' in user_agent or 'captivenetworksupport' in user_agent:
        return render_template('captive_detection.html')
    
    # For actual users, show the main captive portal
    client_mac = get_client_mac()
    client_ip = get_client_ip()
    
    # Check if client is blocked
    if is_client_blocked(client_mac, client_ip):
        return render_template('blocked.html')
    
    # Check if client has a paused session that can be resumed
    paused_session = get_paused_session(client_mac, client_ip)
    if paused_session:
        return render_template('resume.html', 
                              token=paused_session["token"], 
                              remaining_time=paused_session["remaining_time"],
                              auth_method=paused_session["auth_method"],
                              mac=client_mac,
                              ip=client_ip,
                              paused_at=paused_session["paused_at"],
                              pause_expires_at=paused_session["pause_expires_at"])
    
    # Check if client already has an active session
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT token, end_time FROM sessions 
            WHERE mac_address = ? AND ip_address = ? AND is_active = 1 AND is_paused = 0
        ''', (client_mac, client_ip))
        session = cursor.fetchone()
    
    if session:
        token, end_time = session
        # Redirect to session page
        return redirect(url_for('session_status', token=token))
    
    # Log the new client access
    log_event("Portal_Access", f"New client accessing portal", client_mac, client_ip)
    
    # Show login options
    return render_template('portal.html')

# ... keep existing code (authentication routes)

@app.route('/voucher', methods=['POST'])
@limiter.limit("10 per minute")  # Rate limit to prevent brute force
def voucher_login():
    """Handle voucher code submissions"""
    code = request.form.get('code')
    if not code:
        return jsonify({"success": False, "message": "No voucher code provided"}), 400
    
    client_mac = get_client_mac()
    client_ip = get_client_ip()
    
    # Check if client is blocked
    if is_client_blocked(client_mac, client_ip):
        log_security_event("Blocked client login attempt", client_mac=client_mac, client_ip=client_ip)
        return jsonify({"success": False, "message": "Access denied"}), 403
    
    # Check for MAC spoofing
    if check_duplicate_mac(client_mac):
        log_security_event("Possible MAC spoofing detected", client_mac=client_mac, client_ip=client_ip)
        block_client(client_mac, client_ip, "Suspected MAC address spoofing")
        return jsonify({"success": False, "message": "Security violation detected"}), 403
    
    # Validate voucher
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, minutes, is_used FROM vouchers WHERE code = ?', (code,))
        result = cursor.fetchone()
        
        if not result:
            log_event("Invalid_Voucher", f"Invalid voucher code: {code}")
            # Increment failed attempts counter (for rate limiting)
            return jsonify({"success": False, "message": "Invalid voucher code"}), 400
            
        voucher_id, minutes, is_used = result
        
        # Check if voucher is already used
        if is_used:
            log_security_event("Used voucher attempt", client_mac=client_mac, details=code)
            return jsonify({"success": False, "message": "This voucher has already been used"}), 400
        
        # Mark voucher as used
        cursor.execute('''
            UPDATE vouchers SET is_used = 1, used_by = ?, used_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (client_mac, voucher_id))
        conn.commit()
    
    # Create new session
    session_data = create_session(client_mac, client_ip, minutes, "voucher")
    
    return jsonify({
        "success": True, 
        "message": f"Voucher accepted. You have {minutes} minutes of access.",
        "token": session_data["token"],
        "minutes": minutes
    })

@app.route('/session/<token>')
def session_status(token):
    """Show session status page"""
    session_data = validate_session(token)
    if not session_data:
        return redirect(url_for('index'))
    
    # Get session details
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT auth_method, start_time, end_time, total_minutes, is_paused, remaining_seconds 
            FROM sessions WHERE id = ? AND is_active = 1
        ''', (session_data["session_id"],))
        result = cursor.fetchone()
        
        if not result:
            return redirect(url_for('index'))
            
        auth_method, start_time, end_time, total_minutes, is_paused, db_remaining_seconds = result
        
        # If session is paused, use stored remaining seconds
        if is_paused:
            remaining_seconds = db_remaining_seconds
        else:
            # Calculate remaining time
            now = datetime.now()
            end_time_dt = datetime.fromisoformat(end_time)
            remaining_seconds = max(0, int((end_time_dt - now).total_seconds()))
        
    return render_template(
        'session.html', 
        token=token,
        auth_method=auth_method,
        mac=session_data["mac"],
        ip=session_data["ip"],
        total_minutes=total_minutes,
        remaining_seconds=remaining_seconds
    )

@app.route('/pause', methods=['POST'])
def pause_session():
    """Pause a user's active session"""
    token = request.form.get('token')
    if not token:
        return redirect(url_for('index'))
    
    # Validate session
    session_data = validate_session(token)
    if not session_data or session_data.get('is_paused'):
        return redirect(url_for('index'))
    
    # Pause the session
    success, message = pause_session(
        session_data["session_id"], 
        session_data["mac"], 
        session_data["ip"]
    )
    
    if success:
        # Redirect to resume page
        paused_session = get_paused_session(session_data["mac"], session_data["ip"])
        if paused_session:
            return render_template('resume.html', 
                                  token=token,
                                  remaining_time=paused_session["remaining_time"],
                                  auth_method=paused_session["auth_method"],
                                  mac=session_data["mac"],
                                  ip=session_data["ip"],
                                  paused_at=paused_session["paused_at"],
                                  pause_expires_at=paused_session["pause_expires_at"])
    
    # If something went wrong
    return redirect(url_for('session_status', token=token, error=message))

@app.route('/resume', methods=['POST'])
def resume_session():
    """Resume a paused session"""
    token = request.form.get('token')
    if not token:
        return redirect(url_for('index'))
    
    # Find the paused session
    client_mac = get_client_mac()
    client_ip = get_client_ip()
    paused_session = get_paused_session(client_mac, client_ip)
    
    if not paused_session or paused_session["token"] != token:
        return redirect(url_for('index'))
    
    # Resume the session
    success, message = resume_session(
        paused_session["session_id"],
        client_mac,
        client_ip
    )
    
    if success:
        # Redirect to active session page
        return redirect(url_for('session_status', token=token))
    
    # If something went wrong
    return render_template('resume.html',
                          token=token,
                          remaining_time=paused_session["remaining_time"],
                          auth_method=paused_session["auth_method"],
                          mac=client_mac,
                          ip=client_ip,
                          paused_at=paused_session["paused_at"],
                          pause_expires_at=paused_session["pause_expires_at"],
                          error=message)

@app.route('/logout', methods=['POST'])
def logout():
    """End user session"""
    token = request.form.get('token')
    if not token:
        # Check if admin is logged in and handle admin logout
        if session.get('admin_logged_in'):
            session.clear()
            logger.info("Admin logged out")
            return redirect(url_for('admin_login_page'))
        return redirect(url_for('index'))
    
    # Validate session
    session_data = validate_session(token)
    if not session_data:
        return redirect(url_for('index'))
    
    # End session
    end_session(session_data["session_id"])
    
    return redirect(url_for('index'))

# ... keep existing code (API endpoints and admin routes)

@app.route('/api/status', methods=['GET'])
def api_status():
    """API endpoint to check session status"""
    token = request.args.get('token')
    if not token:
        return jsonify({"active": False, "message": "No token provided"}), 400
    
    session_data = validate_session(token)
    if not session_data:
        return jsonify({"active": False, "message": "Session not found or expired"})
    
    # Calculate remaining time
    is_paused = session_data.get('is_paused', False)
    
    if is_paused:
        remaining_seconds = session_data.get('remaining_seconds', 0)
    else:
        now = datetime.now()
        end_time_dt = datetime.fromisoformat(session_data["end_time"])
        remaining_seconds = max(0, int((end_time_dt - now).total_seconds()))
    
    return jsonify({
        "active": True,
        "is_paused": is_paused,
        "remaining_seconds": int(remaining_seconds),
        "mac": session_data["mac"],
        "ip": session_data["ip"],
    })

# ... keep existing code (admin routes)

@app.route('/admin')
def admin_login_page():
    """Admin login page"""
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_login.html')

@app.route('/admin/login', methods=['POST'])
@limiter.limit("5 per minute")  # Strict rate limiting for admin login
def admin_login():
    """Process admin login"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username != ADMIN_USERNAME or not check_password_hash(ADMIN_PASSWORD_HASH, password):
        log_security_event("Failed admin login", details=f"Username: {username}")
        return render_template('admin_login.html', error="Invalid credentials")
    
    session['admin_logged_in'] = True
    log_event("Admin_Login", "Administrator logged in")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/dashboard')
@require_admin
def admin_dashboard():
    """Admin dashboard main page"""
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get active sessions
        cursor.execute('''
            SELECT * FROM sessions WHERE is_active = 1 ORDER BY start_time DESC
        ''')
        active_sessions = cursor.fetchall()
        
        # Get recent logs
        cursor.execute('''
            SELECT * FROM logs ORDER BY timestamp DESC LIMIT 50
        ''')
        recent_logs = cursor.fetchall()
        
        # Get vouchers
        cursor.execute('SELECT * FROM vouchers ORDER BY created_at DESC')
        vouchers = cursor.fetchall()
        
        # Get blocked clients
        cursor.execute('SELECT * FROM blocked_clients ORDER BY blocked_at DESC')
        blocked_clients = cursor.fetchall()
    
    return render_template(
        'admin_dashboard.html',
        active_sessions=active_sessions,
        recent_logs=recent_logs,
        vouchers=vouchers,
        blocked_clients=blocked_clients
    )

# ... keep existing code (more admin routes)

@app.route('/admin/sessions/terminate/<session_id>', methods=['POST'])
@require_admin
def terminate_session(session_id):
    """Terminate a user session"""
    end_session(session_id)
    return redirect(url_for('admin_dashboard', message="Session terminated"))

@app.route('/admin/sessions/pause/<session_id>', methods=['POST'])
@require_admin
def admin_pause_session(session_id):
    """Admin action to pause a user session"""
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT mac_address, ip_address FROM sessions WHERE id = ?', (session_id,))
        result = cursor.fetchone()
        
        if result:
            mac, ip = result
            success, message = pause_session(session_id, mac, ip)
            return redirect(url_for('admin_dashboard', message=f"Session pause: {message}"))
    
    return redirect(url_for('admin_dashboard', error="Session not found"))

@app.route('/admin/sessions/resume/<session_id>', methods=['POST'])
@require_admin
def admin_resume_session(session_id):
    """Admin action to resume a paused session"""
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT mac_address, ip_address FROM sessions WHERE id = ?', (session_id,))
        result = cursor.fetchone()
        
        if result:
            mac, ip = result
            success, message = resume_session(session_id, mac, ip)
            return redirect(url_for('admin_dashboard', message=f"Session resume: {message}"))
    
    return redirect(url_for('admin_dashboard', error="Session not found"))

# ... keep existing code (remaining admin routes and error handlers)

@app.route('/admin/block', methods=['POST'])
@require_admin
def block_client_route():
    """Block a client"""
    mac = request.form.get('mac')
    ip = request.form.get('ip')
    reason = request.form.get('reason')
    duration = request.form.get('duration', type=int, default=24)
    
    if not mac or not reason:
        return redirect(url_for('admin_dashboard', error="Missing required fields"))
    
    block_client(mac, ip, reason, duration)
    return redirect(url_for('admin_dashboard', message="Client blocked"))

@app.route('/admin/unblock/<mac>', methods=['POST'])
@require_admin
def unblock_client(mac):
    """Unblock a client"""
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT ip_address FROM blocked_clients WHERE mac_address = ?', (mac,))
        result = cursor.fetchone()
        
        if result:
            ip = result[0]
            cursor.execute('DELETE FROM blocked_clients WHERE mac_address = ?', (mac,))
            conn.commit()
            
            # Remove firewall rules
            remove_firewall_rules(mac, ip)
            log_event("Client_Unblocked", f"Unblocked client: {mac}")
    
    return redirect(url_for('admin_dashboard', message="Client unblocked"))

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded"""
    log_security_event("Rate limit exceeded", details=str(e.description))
    return jsonify({"success": False, "message": "Too many requests. Please try again later."}), 429

@app.before_request
def before_request():
    """Pre-request processing"""
    if request.path.startswith(('/static/', '/favicon.ico')):
        return  # Skip processing for static resources
    
    client_ip = get_client_ip()
    client_mac = get_client_mac()
    
    # Check if this client is blocked
    if is_client_blocked(client_mac, client_ip) and not request.path.startswith('/admin'):
        if request.is_json:
            return jsonify({"success": False, "message": "Access denied"}), 403
        return render_template('blocked.html'), 403
    
    # Run maintenance tasks periodically
    # In production, this should be a separate background job
    if random.random() < 0.01:  # 1% chance to run maintenance on each request
        maintenance_tasks()

if __name__ == '__main__':
    # For development only - use a proper WSGI server in production
    app.run(host='0.0.0.0', port=5000, debug=True)
