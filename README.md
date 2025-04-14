
# Piso WiFi Fortress

A highly secure hybrid Piso WiFi system that combines TP-Link EAP225 (Omada) access points with custom authentication for voucher and coin-based access.

## Features

- **Secure Captive Portal**: Custom portal with voucher and coin payment options
- **Fort Knox Grade Security**: MAC+IP binding, session tokenization, and comprehensive security measures
- **ESP8266 Coin Slot Integration**: Secure communication between coin slot hardware and backend
- **Admin Dashboard**: Monitor users, generate vouchers, and manage the system
- **Comprehensive Logging**: Track all system activities for auditing
- **Firewall Enforcement**: Automatically configure firewall rules to control access

## Hardware Requirements

- **WiFi Access Point**: TP-Link EAP225 (Omada) or compatible
- **Server**: Windows or Linux machine for running the Flask backend
- **Coin Slot**: ESP8266 connected to a ₱5 coin acceptor module
- **Optional**: Omada Software Controller running on Windows

## System Architecture

The system consists of several components:

1. **Frontend React Application**: Demo UI for development and testing
2. **Python Flask Backend**: Main server that handles authentication, session management, and security
3. **ESP8266 Firmware**: Code for the coin slot module
4. **Firewall Management Scripts**: For configuring system firewall rules

## Setup Instructions

### 1. Backend Server Setup

```bash
# Navigate to the server directory
cd src/server

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the server
python app.py
```

The server will start on http://localhost:5000

### 2. ESP8266 Coin Slot Setup

1. Install Arduino IDE
2. Add ESP8266 board support via Boards Manager
3. Install required libraries:
   - ESP8266WiFi
   - ESP8266HTTPClient
   - WiFiClientSecure
   - ArduinoJson
4. Open `src/arduino/esp8266-coin.ino` in Arduino IDE
5. Update WiFi credentials and server configuration
6. Flash to ESP8266 board

### 3. Firewall Configuration

```bash
# For Linux systems (run as root)
cd src/server
python firewall.py status  # Check current status
python firewall.py whitelist AA:BB:CC:DD:EE:FF 192.168.1.100  # Allow a client

# For Windows systems (run as administrator)
python firewall.py status
```

### 4. Access Point Configuration

1. Set up TP-Link EAP225 with open SSID
2. Configure DHCP to assign consistent IPs to the server
3. Set up port forwarding to direct captive portal requests to the Flask server

## Security Features

- **MAC + IP Binding**: All sessions are tied to client's MAC and IP address
- **Session Tokenization**: Unique tokens for session validation to prevent URL replay attacks
- **Firewall Enforcement**: Only whitelisted MACs/IPs may access the internet
- **Rate Limiting**: Protection against brute force attacks
- **Duplicate MAC Detection**: Prevention of MAC cloning abuse
- **Secure API**: All coin slot requests are authenticated using tokens
- **Comprehensive Logging**: Every action is logged for auditing

## Admin Dashboard

The admin dashboard is accessible at `/admin` and allows:

- Creating and managing vouchers
- Monitoring active sessions
- Viewing system logs
- Blocking suspicious clients

## Demo Access

For demonstration purposes:

- Sample voucher codes: `FREE123` (1 hour) and `TEST456` (2 hours)
- Admin login: username `admin`, password `admin_password` (change in production)

## Production Deployment Recommendations

1. **Enable HTTPS**: Configure SSL certificates for secure connections
2. **Change Default Credentials**: Update all default passwords and API keys
3. **Regular Backups**: Set up automatic backups of the database
4. **System Hardening**: Follow server hardening best practices
5. **Regular Updates**: Keep all components updated with security patches

## License

This project is proprietary and confidential. Unauthorized copying, distribution, or use is strictly prohibited.

