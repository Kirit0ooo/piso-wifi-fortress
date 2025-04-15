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

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key != API_KEY:
            log_security_event("Invalid API key attempt", client_ip=get_client_ip())
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function

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
            (id, mac_address, ip_address, token, auth_method, start_time, end_time, total_minutes, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
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
            SELECT id, mac_address, ip_address, end_time 
            FROM sessions 
            WHERE token = ? AND is_active = 1
        ''', (token,))
        result = cursor.fetchone()
        
        if not result:
            return None
            
        session_id, mac, ip, end_time_str = result
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
            
    return {"session_id": session_id, "mac": mac, "ip": ip, "end_time": end_time_str}

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
            WHERE is_active = 1 AND end_time < ?
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
    
    # Check if client already has an active session
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT token, end_time FROM sessions 
            WHERE (mac_address = ? OR ip_address = ?) AND is_active = 1
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

@app.route('/coin-insert', methods=['POST'])
@require_api_key
@limiter.limit("30 per minute")  # Rate limit to prevent abuse
def coin_insert():
    """Handle coin insertions from ESP8266"""
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "Invalid request"}), 400
    
    # Extract and validate hardware ID
    hardware_id = request.headers.get('X-Hardware-ID')
    if not hardware_id or hardware_id not in KNOWN_DEVICES:
        log_security_event("Unknown hardware device", details=hardware_id)
        return jsonify({"success": False, "message": "Unknown device"}), 401
    
    # Verify request data
    required_fields = ['coins', 'timestamp', 'signature']
    if not all(field in data for field in required_fields):
        return jsonify({"success": False, "message": "Missing required fields"}), 400
    
    # Validate signature (in production, use proper HMAC validation)
    device_secret = KNOWN_DEVICES[hardware_id]['secret']
    expected_sig = str(data['coins']) + str(data['timestamp']) + hardware_id + API_KEY[:5]
    if data['signature'] != expected_sig:
        log_security_event("Invalid coin insert signature", details=hardware_id)
        return jsonify({"success": False, "message": "Invalid signature"}), 401
    
    # Check for tampering flags
    if data.get('tampered', False):
        log_security_event("Device reports tampering", details=hardware_id)
        # You might want to disable the device or take other actions
    
    # Process coin insert
    coins = int(data['coins'])
    if coins <= 0:
        return jsonify({"success": False, "message": "Invalid coin count"}), 400
    
    # Calculate minutes based on coin count
    minutes = coins * (25 / COIN_RATE)  # ₱5 = 25 mins
    
    # Log the coin insertion
    log_event("Coin_Insert", f"{coins} coins inserted from {hardware_id}", 
             details=json.dumps({"coins": coins, "minutes": minutes}))
    
    # In a real system, we would associate this with a specific client
    # For now, we'll just return success and track the amount
    return jsonify({
        "success": True,
        "message": f"{coins} coins processed. {minutes} minutes added.",
        "minutes": minutes
    })

@app.route('/coin-activate', methods=['POST'])
@limiter.limit("10 per minute")
def coin_activate():
    """Activate a client session after coin insertion"""
    # This would be called from the client side after coins have been inserted
    # In a real system, this would require a token from the coin-insert endpoint
    
    client_mac = get_client_mac()
    client_ip = get_client_ip()
    
    # Check if client is blocked
    if is_client_blocked(client_mac, client_ip):
        return jsonify({"success": False, "message": "Access denied"}), 403
    
    coins = request.form.get('coins', type=int)
    if not coins or coins <= 0:
        return jsonify({"success": False, "message": "Invalid coin amount"}), 400
    
    # Calculate minutes based on coins
    minutes = coins * (25 / COIN_RATE)  # ₱5 = 25 mins
    
    # Create session
    session_data = create_session(client_mac, client_ip, minutes, "coins")
    
    return jsonify({
        "success": True, 
        "message": f"Access granted for {minutes} minutes",
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
            SELECT auth_method, start_time, end_time, total_minutes 
            FROM sessions WHERE id = ? AND is_active = 1
        ''', (session_data["session_id"],))
        result = cursor.fetchone()
        
        if not result:
            return redirect(url_for('index'))
            
        auth_method, start_time, end_time, total_minutes = result
        
        # Calculate remaining time
        now = datetime.now()
        end_time_dt = datetime.fromisoformat(end_time)
        remaining_seconds = max(0, (end_time_dt - now).total_seconds())
        
    return render_template(
        'session.html', 
        token=token,
        auth_method=auth_method,
        mac=session_data["mac"],
        ip=session_data["ip"],
        total_minutes=total_minutes,
        remaining_seconds=int(remaining_seconds)
    )

@app.route('/logout', methods=['POST'])
def logout():
    """End user session"""
    token = request.form.get('token')
    if not token:
        return redirect(url_for('index'))
    
    # Validate session
    session_data = validate_session(token)
    if not session_data:
        return redirect(url_for('index'))
    
    # End session
    end_session(session_data["session_id"])
    
    return redirect(url_for('index'))

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
    now = datetime.now()
    end_time_dt = datetime.fromisoformat(session_data["end_time"])
    remaining_seconds = max(0, (end_time_dt - now).total_seconds())
    
    return jsonify({
        "active": True,
        "remaining_seconds": int(remaining_seconds),
        "mac": session_data["mac"],
        "ip": session_data["ip"],
    })

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

@app.route('/admin/vouchers/create', methods=['POST'])
@require_admin
def create_voucher():
    """Create new voucher codes"""
    count = request.form.get('count', type=int, default=1)
    minutes = request.form.get('minutes', type=int, default=60)
    
    if count < 1 or count > 100 or minutes < 5:
        return redirect(url_for('admin_dashboard', error="Invalid voucher parameters"))
    
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        vouchers_created = []
        
        for _ in range(count):
            # Generate random code
            code = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(8))
            voucher_id = str(uuid.uuid4())
            
            cursor.execute(
                "INSERT INTO vouchers (id, code, minutes) VALUES (?, ?, ?)",
                (voucher_id, code, minutes)
            )
            vouchers_created.append(code)
            
        conn.commit()
    
    log_event("Vouchers_Created", f"Created {count} vouchers", 
             details=json.dumps({"minutes": minutes, "codes": vouchers_created}))
    
    return redirect(url_for('admin_dashboard', message=f"Created {count} vouchers"))

@app.route('/admin/sessions/terminate/<session_id>', methods=['POST'])
@require_admin
def terminate_session(session_id):
    """Terminate a user session"""
    end_session(session_id)
    return redirect(url_for('admin_dashboard', message="Session terminated"))

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
