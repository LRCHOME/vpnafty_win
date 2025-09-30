#!/bin/bash

# Configuration
SCRIPT_VERSION="2.2.5"
API_BASE="https://api.rtscom.com/liberator"
REGISTER_ENDPOINT="$API_BASE/register"
HEARTBEAT_ENDPOINT="$API_BASE/heartbeats"
CONFIG_DIR="/etc/libera-agent"
KEY_FILE="$CONFIG_DIR/registration.key"
IP_FILE="$CONFIG_DIR/last_ip.txt"
LOG_FILE="/var/log/libera-agent.log"
COMMANDS_LOG="/var/log/libera-commands.log"
HEARTBEAT_INTERVAL=60

SERVICE_NAME="libera-agent"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SCRIPT_PATH="/usr/local/bin/libera-agent.sh"

# Xray and proxy configuration
XRAY_DIR="/usr/local/etc/xray"
CONFIG_FILE="$XRAY_DIR/config.json"
XRAY_BIN="/usr/local/bin/xray"
REDSOCKS_PORT=12345
PROXY_SOCKS_PORT=10808

# Network variables
DEFAULT_IF=""
LOCAL_IP=""
NETWORK=""
API_IP=""
VPS_IP=""

# Create config directory
mkdir -p "$CONFIG_DIR"

# Simple logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Command logging function
log_command() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - COMMAND: $1" >> "$COMMANDS_LOG"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Error: This script must be run as root (use sudo)"
        exit 1
    fi
}

# Get current script version
get_script_version() {
    echo "$SCRIPT_VERSION"
}

# Get current xray version
get_xray_version() {
    if [ -f "$XRAY_BIN" ]; then
        local version=$($XRAY_BIN version 2>/dev/null | head -1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1)
        if [ -n "$version" ]; then
            echo "$version"
        else
            echo "unknown"
        fi
    else
        echo "not-installed"
    fi
}

# Get system architecture
get_architecture() {
    local arch=$(uname -m)
    case "$arch" in
        "x86_64") echo "x64" ;;
        "aarch64") echo "arm64" ;;
        "armv7l"|"armv6l") echo "arm" ;;
        "i386"|"i686") echo "x86" ;;
        *) echo "$arch" ;;
    esac
}

# Setup log rotation
setup_log_rotation() {
    log "Setting up log rotation..."

    cat > /etc/logrotate.d/libera-agent << 'EOF'
/var/log/libera-agent.log
/var/log/libera-commands.log
/var/log/libera-metrics.log
{
    daily
    rotate 7
    maxsize 50M
    missingok
    notifempty
    compress
    delaycompress
    create 644 root root
    sharedscripts
    postrotate
        systemctl reload libera-agent 2>/dev/null || true
    endscript
}

/var/log/xray/*.log
/var/log/redsocks.log
{
    daily
    rotate 3
    maxsize 100M
    missingok
    notifempty
    compress
    delaycompress
    create 644 nobody nogroup
        systemctl restart xray > /dev/null 2>&1 || true
    endscript
}
EOF

    log "Log rotation configured with 7-day retention and 50MB max size"
    return 0
}

# Remove log rotation config
remove_log_rotation() {
    log "Removing log rotation configuration..."
    rm -f /etc/logrotate.d/libera-agent
    return 0
}


# Detect network configuration
detect_network_config() {
    log "Detecting network configuration..."

    # Get default interface
    DEFAULT_IF=$(ip route | grep '^default' | awk '{print $5}' | head -1)
    if [ -z "$DEFAULT_IF" ]; then
        log "ERROR: Cannot detect default network interface"
        return 1
    fi

    # Get local IP and subnet
    LOCAL_IP=$(ip addr show $DEFAULT_IF | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -1)
    local subnet=$(ip addr show $DEFAULT_IF | grep 'inet ' | awk '{print $2}' | head -1)

    if [ -z "$LOCAL_IP" ] || [ -z "$subnet" ]; then
        log "ERROR: Cannot detect IP address for interface $DEFAULT_IF"
        return 1
    fi

    # Calculate network range
    NETWORK=$(echo $subnet | cut -d/ -f1 | cut -d. -f1-3).0/24

    log "Network detected: Interface=$DEFAULT_IF, IP=$LOCAL_IP, Network=$NETWORK"
    return 0
}

# Get IP addresses to exclude from proxy
get_exclusion_ips() {
    log "Resolving exclusion IP addresses..."

    # Extract API server from URL
    local api_host=$(echo "$API_BASE" | sed 's|https\?://||' | cut -d'/' -f1)

    # Resolve API IP with multiple attempts
    API_IP=""
    if command -v dig >/dev/null 2>&1; then
        API_IP=$(dig +short +time=5 +tries=2 $api_host | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    fi

    # Fallback to nslookup if dig fails
    if [ -z "$API_IP" ] && command -v nslookup >/dev/null 2>&1; then
        API_IP=$(nslookup $api_host | grep -A 10 'Non-authoritative answer:' | grep 'Address:' | awk '{print $2}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    fi

    if [ -z "$API_IP" ]; then
        log "WARNING: Failed to resolve API IP for $api_host, API traffic may be routed through proxy"
        API_IP=""
    else
        log "API server IP resolved: $API_IP"
    fi

    # Extract VPS IP from xray config
    VPS_IP=""
    if [ -f "$CONFIG_FILE" ]; then
        VPS_IP=$(grep -A 20 '"tag": "proxy"' "$CONFIG_FILE" 2>/dev/null | grep -o '"address": "[^"]*"' | head -1 | cut -d'"' -f4)
        if [ -n "$VPS_IP" ]; then
            log "VPS server IP from config: $VPS_IP"
        fi
    fi

    return 0
}

# Install required packages
install_dependencies() {
    log "Installing dependencies..."

    # Update package lists
    if ! apt update; then
        log "ERROR: Failed to update package lists"
        return 1
    fi

    # Install curl for API communication
    if ! command -v curl >/dev/null 2>&1; then
        log "Installing curl for API communication..."
        if ! apt install -y curl; then
            log "ERROR: Failed to install curl"
            return 1
        fi
    fi

    # Install wget for downloading binaries
    if ! command -v wget >/dev/null 2>&1; then
        log "Installing wget for binary downloads..."
        if ! apt install -y wget; then
            log "ERROR: Failed to install wget"
            return 1
        fi
    fi

    # Install jq for JSON parsing
    if ! command -v jq >/dev/null 2>&1; then
        log "Installing jq for JSON parsing..."
        apt install -y jq || log "WARNING: jq installation failed, using fallback JSON parser"
    fi

    # Install dig for DNS resolution
    if ! command -v dig >/dev/null 2>&1; then
        log "Installing dnsutils for DNS resolution..."
        apt install -y dnsutils || log "WARNING: Failed to install dnsutils, will try nslookup fallback"
    fi

    # Install iptables and persistence
    if ! command -v iptables >/dev/null 2>&1; then
        log "Installing iptables..."
        if ! apt install -y iptables; then
            log "ERROR: Failed to install iptables"
            return 1
        fi
    fi

    if ! dpkg -l | grep -q iptables-persistent; then
        log "Installing iptables-persistent..."
        if ! DEBIAN_FRONTEND=noninteractive apt install -y iptables-persistent; then
            log "ERROR: Failed to install iptables-persistent"
            return 1
        fi
    fi

    # Install redsocks
    if ! dpkg -l | grep -q redsocks; then
        log "Installing redsocks..."
        if ! apt install -y redsocks; then
            log "ERROR: Failed to install redsocks"
            return 1
        fi
    fi

    # Install ss utility (iproute2) for better connection monitoring
    if ! command -v ss >/dev/null 2>&1; then
        log "Installing iproute2 for connection monitoring..."
        apt install -y iproute2 || log "WARNING: Failed to install iproute2"
    fi

    # Enable persistence services
    systemctl enable netfilter-persistent >/dev/null 2>&1 || true
    systemctl enable redsocks >/dev/null 2>&1 || true

    log "Dependencies installed successfully"
    return 0
}

# Setup transparent proxy iptables rules
setup_transparent_proxy() {
    log "Setting up transparent proxy..."

    # Detect current network configuration
    if ! detect_network_config; then
        log "ERROR: Failed to detect network configuration"
        return 1
    fi

    # Get exclusion IPs
    if ! get_exclusion_ips; then
        log "WARNING: Failed to get all exclusion IPs, continuing anyway"
    fi

    # Enable IP forwarding
    local current_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    if [ "$current_forward" != "1" ]; then
        log "Enabling IP forwarding..."
        sysctl -w net.ipv4.ip_forward=1
        if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
            echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
        fi
    fi

    # Clean any existing XRAY chain
    teardown_transparent_proxy_rules

    # Create XRAY iptables chain
    log "Creating XRAY iptables chain..."
    iptables -t nat -N XRAY 2>/dev/null || true


    # Add exclusion rules FIRST (highest priority)
    log "Adding exclusion rules..."

    # Loopback
    iptables -t nat -A XRAY -d 127.0.0.0/8 -j RETURN

    # Local networks exclusions
	iptables -t nat -A XRAY -s $NETWORK -d $NETWORK -j RETURN
    iptables -t nat -A XRAY -d 10.0.0.0/8 -j RETURN
    iptables -t nat -A XRAY -d 172.16.0.0/12 -j RETURN
    iptables -t nat -A XRAY -d 169.254.0.0/16 -j RETURN
    iptables -t nat -A XRAY -d 224.0.0.0/4 -j RETURN

    # API and VPS exclusions
    if [ -n "$API_IP" ]; then
        iptables -t nat -A XRAY -d $API_IP -j RETURN
        log "Added API server exclusion: $API_IP"
    fi

    if [ -n "$VPS_IP" ]; then
        iptables -t nat -A XRAY -d $VPS_IP -j RETURN
        log "Added VPS server exclusion: $VPS_IP"
    fi

    # Redirect all other TCP traffic to redsocks
    iptables -t nat -A XRAY -p tcp -j REDIRECT --to-ports $REDSOCKS_PORT

    # Apply XRAY chain to client traffic from LAN
    iptables -t nat -A PREROUTING -i $DEFAULT_IF -p tcp -s $NETWORK -j XRAY
    
    # Add DNS redirect to prevent DNS leaks (clients use RPi's DNS)
    iptables -t nat -A PREROUTING -s $NETWORK -p udp --dport 53 -j REDIRECT --to-port 53
    log "Added DNS redirect for clients"

    # MASQUERADE for VPS traffic
    if [ -n "$VPS_IP" ]; then
        iptables -t nat -A POSTROUTING -s $NETWORK -d $VPS_IP -o $DEFAULT_IF -j MASQUERADE
    fi
    
    # Allow forwarding
    iptables -A FORWARD -s $NETWORK -j ACCEPT
    iptables -A FORWARD -d $NETWORK -j ACCEPT

    # Save rules
    save_iptables

    log "Transparent proxy configured for CLIENT traffic only"
    return 0
}

teardown_transparent_proxy() {
    log "Tearing down transparent proxy..."
    
    # Stop redsocks service
    systemctl stop redsocks 2>/dev/null || true
    
    # Remove iptables rules
    teardown_transparent_proxy_rules
    
    # Save clean iptables
    save_iptables >/dev/null 2>&1 || true
    
    log "Transparent proxy teardown complete"
    return 0
}


# Remove transparent proxy iptables rules
teardown_transparent_proxy_rules() {
    log "Cleaning up transparent proxy rules..."
    
    # Flush entire chains
    iptables -t nat -F PREROUTING 2>/dev/null || true
    iptables -t nat -F POSTROUTING 2>/dev/null || true
    iptables -F FORWARD 2>/dev/null || true
    
    # Delete XRAY chain
    iptables -t nat -F XRAY 2>/dev/null || true
    iptables -t nat -X XRAY 2>/dev/null || true
    
    log "Transparent proxy rules cleaned"
    return 0
}

# Save iptables rules for persistence
save_iptables() {
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        return 0
    fi
    return 1
}

# Configure redsocks
configure_redsocks() {
    log "Configuring redsocks..."

    cat > /etc/redsocks.conf << EOF
base {
    log_debug = off;
    log_info = on;
    log = "file:/var/log/redsocks.log";
    daemon = on;
    redirector = iptables;
}

redsocks {
    local_ip = 0.0.0.0;
    local_port = $REDSOCKS_PORT;
    ip = 127.0.0.1;
    port = $PROXY_SOCKS_PORT;
    type = socks5;
}
EOF

    return 0
}

# Start transparent proxy services
start_transparent_proxy_services() {
    log "Starting transparent proxy services..."

    # Ensure xray is running first (redsocks connects to it)
    if ! systemctl is-active --quiet xray; then
        log "Starting xray service..."
        if ! systemctl start xray; then
            log "ERROR: Failed to start xray service"
            return 1
        fi
        sleep 3
    fi

    # Configure and start redsocks
    if ! configure_redsocks; then
        log "ERROR: Failed to configure redsocks"
        return 1
    fi

    if ! systemctl restart redsocks; then
        log "ERROR: Failed to start redsocks service"
        return 1
    fi

    # Wait and verify services are running
    sleep 2
    if ! systemctl is-active --quiet xray; then
        log "ERROR: Xray service failed to start properly"
        return 1
    fi

    if ! systemctl is-active --quiet redsocks; then
        log "ERROR: Redsocks service failed to start properly"
        return 1
    fi

    log "Transparent proxy services started successfully"
    return 0
}

# Reconfigure proxy on network change
reconfigure_proxy_on_change() {
    log "Network changed detected, reconfiguring transparent proxy..."

    # Stop services gracefully
    systemctl stop redsocks 2>/dev/null || true

    # Reconfigure with new network settings
    if setup_transparent_proxy && start_transparent_proxy_services; then
        log "Transparent proxy reconfigured successfully"
        return 0
    else
        log "ERROR: Failed to reconfigure transparent proxy"
        return 1
    fi
}

# Generate default xray config
generate_default_config() {
    log "Generating default xray config..."
    mkdir -p "$XRAY_DIR" /var/log/xray

    cat > "$CONFIG_FILE" << 'EOF'
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "tag": "socks",
      "port": 10808,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": {"udp": true}
    },
    {
      "tag": "http",
      "port": 10809,
      "listen": "127.0.0.1",
      "protocol": "http"
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "vnext": [{
          "address": "example.com",
          "port": 443,
          "users": [{
            "id": "00000000-0000-0000-0000-000000000000",
            "encryption": "none",
            "flow": "xtls-rprx-vision"
          }]
        }]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "fingerprint": "chrome",
          "serverName": "www.microsoft.com",
          "publicKey": "placeholder",
          "shortId": "00000000",
          "spiderX": "/"
        }
      }
    },
    {
      "tag": "direct",
      "protocol": "freedom"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "outboundTag": "direct",
        "domain": ["geosite:private"]
      },
      {
        "type": "field",
        "outboundTag": "proxy",
        "network": "tcp,udp"
      }
    ]
  }
}
EOF

    chmod 644 "$CONFIG_FILE"
    log "Default config created: $CONFIG_FILE"
    return 0
}

# Install Xray with transparent proxy
install_xray() {
    log "Installing Xray with transparent proxy capabilities..."

    # Install dependencies first
    if ! install_dependencies; then
        log "ERROR: Failed to install dependencies"
        return 1
    fi

    # Install Xray binary if not present
    if [ ! -f "$XRAY_BIN" ]; then
        log "Installing Xray binary..."
        if ! bash -c "$(wget -O- https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install; then
            log "ERROR: Failed to install Xray binary"
            return 1
        fi
        systemctl enable xray
        log "Xray binary installed and enabled"
    else
        log "Xray already installed: $(get_xray_version)"
    fi

    # Create default config
    if ! generate_default_config; then
        log "ERROR: Failed to generate default config"
        return 1
    fi

    # Start xray with default config
    log "Starting Xray service..."
    if ! systemctl start xray; then
        log "WARNING: Xray failed to start with default config"
    fi

    # Setup transparent proxy by default
    log "Setting up transparent proxy (required for gateway mode)..."
    if setup_transparent_proxy && start_transparent_proxy_services; then
        log "Transparent proxy setup completed successfully"
        log "Gateway IP: $LOCAL_IP"
        log "Network: $NETWORK"
        log "Configure other devices to use $LOCAL_IP as gateway"
    else
        log "WARNING: Transparent proxy setup failed, continuing without proxy"
        # Don't fail installation if proxy fails - device can still work
    fi

    return 0
}

# Uninstall everything
uninstall_everything() {
    log "Uninstalling Xray and cleaning up transparent proxy..."

    # Stop libera-agent service first
    systemctl stop "$SERVICE_NAME.service" 2>/dev/null || true

    # Teardown transparent proxy completely
    teardown_transparent_proxy

    # Stop all services
    systemctl stop xray 2>/dev/null || true
    systemctl stop redsocks 2>/dev/null || true
    systemctl disable xray 2>/dev/null || true
    systemctl disable redsocks 2>/dev/null || true

    # Remove xray using official script
    if [ -f "$XRAY_BIN" ]; then
        log "Removing Xray binary..."
        if command -v wget >/dev/null 2>&1; then
            bash -c "$(wget -O- https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge 2>/dev/null || true
        else
            rm -f "$XRAY_BIN" 2>/dev/null || true
        fi
    fi

    # Remove redsocks package
    if dpkg -l | grep -q redsocks; then
        log "Removing redsocks package..."
        apt remove --purge -y redsocks 2>/dev/null || true
    fi

    # Clean configuration files
    log "Cleaning configuration files..."
    rm -rf "$XRAY_DIR" 2>/dev/null || true
    rm -f /etc/redsocks.conf 2>/dev/null || true
    rm -rf /var/log/xray 2>/dev/null || true
    rm -f /var/log/redsocks.log 2>/dev/null || true

    # Clean libera-agent files (but preserve service for proper uninstall)
    rm -f "$KEY_FILE" 2>/dev/null || true
    rm -f "$IP_FILE" 2>/dev/null || true

    # Remove log rotation
    remove_log_rotation

    # Final iptables cleanup and save
    teardown_transparent_proxy_rules
    save_iptables

    log "Complete uninstall finished successfully"
    return 0
}

# Create systemd service file
create_service_file() {
    cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=Libera API Agent with Transparent Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/libera-agent.sh run
Restart=always
RestartSec=30
User=root
Group=root

# Logging - removed duplicate logging
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
}

# Install systemd service
install_service() {
    echo "=== Installing Libera Agent Service ==="

    check_root

    # Install Xray and transparent proxy first
    if ! install_xray; then
        echo "ERROR: Failed to install Xray and transparent proxy"
        exit 1
    fi

    # Setup log rotation
    setup_log_rotation

    # Copy script
    if [ "$0" != "$SCRIPT_PATH" ]; then
        echo "Copying script to $SCRIPT_PATH..."
        cp "$0" "$SCRIPT_PATH"
        chmod +x "$SCRIPT_PATH"
        echo "✓ Script copied"
    fi

    # Create service
    echo "Creating systemd service..."
    create_service_file
    echo "✓ Service file created"

    # Install service
    echo "Installing service..."
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME.service"
    echo "✓ Service enabled"

    # Start service
    echo "Starting service..."
    systemctl start "$SERVICE_NAME.service"
    echo "✓ Service started"

    echo ""
    echo "=== Installation Complete! ==="
    echo "Xray service: $(systemctl is-active xray || echo 'needs configuration')"
    echo "Redsocks service: $(systemctl is-active redsocks || echo 'inactive')"
    echo "Transparent proxy: $([ -n "$(iptables -t nat -L XRAY 2>/dev/null)" ] && echo 'enabled' || echo 'disabled')"
    echo "Log rotation: configured (7 days retention, 50MB max size)"
    echo ""
    echo "Service status:"
    systemctl status "$SERVICE_NAME.service" --no-pager
    echo ""
    echo "Gateway Configuration:"
    detect_network_config >/dev/null 2>&1 || true
    echo "  Set gateway IP to: $LOCAL_IP on other devices"
    echo "  Network range: $NETWORK"
    echo ""
    echo "Commands:"
    echo "  sudo systemctl status libera-agent      # Check status"
    echo "  sudo journalctl -u libera-agent -f     # View logs"
    echo "  sudo $SCRIPT_PATH status               # Detailed status with metrics"
    echo "  sudo $SCRIPT_PATH uninstall-proxy      # Remove everything"
}

# Get UUID
get_uuid() {
    cat /proc/cpuinfo | grep Serial | awk '{print $3}'
}

# Get external IP - no more need for --noproxy
get_external_ip() {
    local ip=""
    
    # Now these will work directly without proxy
    ip=$(curl -s --max-time 10 ifconfig.me 2>/dev/null)
    if [ -z "$ip" ]; then
        ip=$(curl -s --max-time 10 ipinfo.io/ip 2>/dev/null)
    fi
    if [ -z "$ip" ]; then
        ip=$(curl -s --max-time 10 icanhazip.com 2>/dev/null)
    fi
    
    echo "$ip"
}

# Get internal/local IP - simplified
get_internal_ip() {
    # Get first non-loopback IPv4 address
    ip -4 addr show | grep -oP 'inet \K[\d.]+' | grep -v '^127\.' | head -1
}

# Get uptime in seconds
get_uptime() {
    awk '{print int($1)}' /proc/uptime
}

# Get traffic stats - simple version
get_traffic_stats() {
    local rx_bytes=0
    local tx_bytes=0
    
    # Just get total bytes, no packets needed
    while read -r line; do
        if [[ "$line" =~ ^[[:space:]]*(eth|ens|enp|wlan) ]]; then
            local values=($line)
            rx_bytes=$((rx_bytes + ${values[1]:-0}))
            tx_bytes=$((tx_bytes + ${values[9]:-0}))
        fi
    done < /proc/net/dev
    
    printf '{"rx_bytes":%d,"tx_bytes":%d}' $rx_bytes $tx_bytes
}

# Check xray service
check_xray_service() {
    if systemctl is-active --quiet xray.service; then
        echo "running"
    else
        echo "stopped"
    fi
}

# Update script
update_script() {
    log "Updating script from API..."
    log_command "Update - Starting script update"

    local arch=$(get_architecture)
    log "Detected architecture: $arch"

    # Download architecture-specific script
    local temp_script="/tmp/libera-agent-new.sh"
    local download_url="$API_BASE/update/${arch}/libera-agent.sh"

    log "Downloading script from: $download_url"
    if ! curl -s --max-time 60 "$download_url" -o "$temp_script"; then
        log "ERROR: Failed to download script from API"
        log_command "Update FAILED - script download failed"
        return 1
    fi

    # Check if download worked
    if [ ! -f "$temp_script" ] || [ ! -s "$temp_script" ]; then
        log "ERROR: Downloaded script is empty or missing"
        log_command "Update FAILED - script file empty"
        rm -f "$temp_script"
        return 1
    fi

    # Basic validation - check if it's a bash script
    if ! head -1 "$temp_script" | grep -q "#!/bin/bash"; then
        log "ERROR: Downloaded file is not a valid bash script"
        log_command "Update FAILED - invalid script file"
        rm -f "$temp_script"
        return 1
    fi

    # Backup current script
    if ! cp "$SCRIPT_PATH" "$SCRIPT_PATH.backup"; then
        log "ERROR: Failed to create backup of current script"
        log_command "Update FAILED - backup creation failed"
        rm -f "$temp_script"
        return 1
    fi

    # Install new script
    chmod +x "$temp_script"
    if mv "$temp_script" "$SCRIPT_PATH"; then
        log "Script successfully updated"
        log_command "Update SUCCESS - Script updated"

        # Restart service to use new script
        log "Restarting libera-agent service with new script..."
        systemctl restart "$SERVICE_NAME.service" &
        return 0
    else
        log "ERROR: Failed to install new script"
        log_command "Update FAILED - script install failed"

        # Restore backup
        if [ -f "$SCRIPT_PATH.backup" ]; then
            mv "$SCRIPT_PATH.backup" "$SCRIPT_PATH"
            log "Restored backup script"
        fi
        rm -f "$temp_script"
        return 1
    fi
}

# Update xray
update_xray() {
    log "Updating xray from API..."
    log_command "Update - Starting xray update"

    local arch=$(get_architecture)
    log "Detected architecture: $arch"

    # Download architecture-specific xray binary
    local temp_xray="/tmp/xray-new"
    local download_url="$API_BASE/update/${arch}/xray"

    log "Downloading xray from: $download_url"
    if ! curl -s --max-time 120 "$download_url" -o "$temp_xray"; then
        log "ERROR: Failed to download xray binary from API"
        log_command "Update FAILED - xray download failed"
        return 1
    fi

    # Check if download worked
    if [ ! -f "$temp_xray" ] || [ ! -s "$temp_xray" ]; then
        log "ERROR: Downloaded xray binary is empty or missing"
        log_command "Update FAILED - xray file empty"
        rm -f "$temp_xray"
        return 1
    fi

    # Stop services during update
    log "Stopping services for update..."
    systemctl stop redsocks 2>/dev/null || true
    systemctl stop xray 2>/dev/null || true

    # Backup current xray binary
    if [ -f "$XRAY_BIN" ]; then
        if ! cp $XRAY_BIN $XRAY_BIN.backup; then
            log "ERROR: Failed to backup current xray binary"
            log_command "Update FAILED - xray backup failed"
            systemctl start xray
            rm -f "$temp_xray"
            return 1
        fi
        log "Current xray backed up"
    fi

    # Install new xray binary
    chmod +x "$temp_xray"
    if mv "$temp_xray" $XRAY_BIN; then
        log "New xray binary installed"

        # Test new binary
        log "Testing new xray binary..."
        if $XRAY_BIN version >/dev/null 2>&1; then
            local new_version=$($XRAY_BIN version 2>/dev/null | head -1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1)
            log "New xray version: $new_version"

            # Start services with new binary
            if systemctl start xray && start_transparent_proxy_services; then
                log "Services started successfully with new version"
                log_command "Update SUCCESS - Xray updated to $new_version"

                # Clean up backup after successful update
                rm -f $XRAY_BIN.backup
                return 0
            else
                log "ERROR: Failed to start services with new binary"
                log_command "Update FAILED - service start failed"
            fi
        else
            log "ERROR: New xray binary is corrupted or incompatible"
            log_command "Update FAILED - new xray binary broken"
        fi

        # Restore backup if we get here
        log "Restoring backup xray binary..."
        if [ -f "$XRAY_BIN.backup" ]; then
            mv $XRAY_BIN.backup $XRAY_BIN
            if systemctl start xray && start_transparent_proxy_services; then
                log "Restored backup xray and restarted services"
            else
                log "ERROR: Failed to restart even the backup xray"
            fi
        fi

        return 1
    else
        log "ERROR: Failed to install new xray binary"
        log_command "Update FAILED - xray install failed"
        systemctl start xray
        start_transparent_proxy_services
        rm -f "$temp_xray"
        return 1
    fi
}

# Parse VLESS URL
parse_vless() {
    local url="$1"

    if [ -z "$url" ]; then
        log "ERROR: Empty vless URL"
        return 1
    fi

    # Clean and validate - use the working version's approach
    url=$(echo "$url" | sed 's/vless:\/\/.*vless:/vless:/')

    if [[ ! "$url" =~ ^vless:// ]]; then
        log "ERROR: Invalid vless URL"
        return 1
    fi

    # Extract components - use working sed commands
    UUID=$(echo "$url" | sed 's/vless:\/\/\([^@]*\)@.*/\1/')
    SERVER_PORT=$(echo "$url" | sed 's/.*@\([^/?]*\).*/\1/')
    SERVER=$(echo "$SERVER_PORT" | cut -d: -f1)
    PORT=$(echo "$SERVER_PORT" | cut -d: -f2)
    PARAMS=$(echo "$url" | sed 's/.*?\(.*\)#.*/\1/')

    # Validate required
    if [ -z "$UUID" ] || [ -z "$SERVER" ] || [ -z "$PORT" ]; then
        log "ERROR: Missing UUID/SERVER/PORT in vless URL"
        return 1
    fi

    # Parse parameters
    SNI=$(echo "$PARAMS" | grep -o 'sni=[^&]*' | cut -d= -f2 | sed 's/%20/ /g')
    PBK=$(echo "$PARAMS" | grep -o 'pbk=[^&]*' | cut -d= -f2)
    SID=$(echo "$PARAMS" | grep -o 'sid=[^&]*' | cut -d= -f2)
    FLOW=$(echo "$PARAMS" | grep -o 'flow=[^&]*' | cut -d= -f2)
    FP=$(echo "$PARAMS" | grep -o 'fp=[^&]*' | cut -d= -f2)
    SPX=$(echo "$PARAMS" | grep -o 'spx=[^&]*' | cut -d= -f2 | sed 's/%2F/\//g')

    # Defaults
    FLOW="${FLOW:-xtls-rprx-vision}"
    SPX="${SPX:-/}"
    FP="${FP:-chrome}"

    return 0
}

# Generate xray config from VLESS URL
generate_config() {
    local vless_url="$1"

    log "Generating xray config for $SERVER:$PORT"
    mkdir -p "$XRAY_DIR" /var/log/xray

    cat > "$CONFIG_FILE" << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "tag": "socks",
      "port": $PROXY_SOCKS_PORT,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": {"udp": true}
    },
    {
      "tag": "http",
      "port": 10809,
      "listen": "127.0.0.1",
      "protocol": "http"
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "vnext": [{
          "address": "$SERVER",
          "port": $PORT,
          "users": [{
            "id": "$UUID",
            "encryption": "none",
            "flow": "$FLOW"
          }]
        }]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "fingerprint": "$FP",
          "serverName": "$SNI",
          "publicKey": "$PBK",
          "shortId": "$SID",
          "spiderX": "$SPX"
        }
      }
    },
    {
      "tag": "direct",
      "protocol": "freedom"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "outboundTag": "direct",
        "domain": ["geosite:private"]
      },
      {
        "type": "field",
        "outboundTag": "proxy",
        "network": "tcp,udp"
      }
    ]
  }
}
EOF

    chmod 644 "$CONFIG_FILE"
    log "Config created: $CONFIG_FILE"
    return 0
}

# Command: KeyChange
handle_keychange() {
    local vless_url="$1"

    log_command "KeyChange - New configuration received"

    # Parse URL
    if ! parse_vless "$vless_url"; then
        log_command "KeyChange FAILED - Invalid vless URL"
        return 1
    fi

    log_command "KeyChange - Server: $SERVER:$PORT"

    # Backup old config
    [ -f "$CONFIG_FILE" ] && cp "$CONFIG_FILE" "$CONFIG_FILE.backup"

    # Generate new config
    generate_config "$vless_url"

    # Restart services with new config
    if handle_restart; then
        # Reconfigure transparent proxy with new VPS IP
        if reconfigure_proxy_on_change; then
            log_command "KeyChange SUCCESS - Config updated and proxy reconfigured"
            return 0
        else
            log_command "KeyChange PARTIAL - Config updated but proxy failed"
            return 1
        fi
    else
        log_command "KeyChange FAILED - Service restart failed, restoring backup"
        # Restore backup
        [ -f "$CONFIG_FILE.backup" ] && mv "$CONFIG_FILE.backup" "$CONFIG_FILE"
        handle_restart  # Try to restart with old config
        return 1
    fi
}

# Command: Restart
handle_restart() {
    log_command "Restart - Restarting xray service"

    if systemctl restart xray.service; then
        log_command "Restart SUCCESS"
        log "Xray service restarted"
        return 0
    else
        log_command "Restart FAILED"
        return 1
    fi
}

# Command: Update
handle_update() {
    local json_response="$1"
    local body=""

    if command -v jq >/dev/null 2>&1; then
        body=$(echo "$json_response" | jq -r '.body // empty' 2>/dev/null)
    else
        body=$(echo "$json_response" | sed -n 's/.*"body"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    fi

    if [ -z "$body" ]; then
        log_command "Update FAILED - no body"
        return 1
    fi

    log_command "Update - Updating: $body"

    case "$body" in
        "script")
            update_script
            ;;
        "xray")
            update_xray
            ;;
        *)
            log_command "Update FAILED - unknown program: $body"
            return 1
            ;;
    esac
}

# Command: Shutdown
handle_shutdown() {
    log_command "Shutdown - Stopping services"

    teardown_transparent_proxy
    systemctl stop xray.service
    systemctl stop "$SERVICE_NAME.service"

    log_command "Shutdown - Services stopped"
    log "Shutdown command executed"
    exit 0
}

# Process API commands with better JSON parsing
process_commands() {
    local json_response="$1"

    # Check if response is empty or empty JSON
    if [ -z "$json_response" ] || [ "$json_response" = "{}" ]; then
        return 0
    fi

    local command=""
    local body=""

    # Use jq if available for robust JSON parsing
    if command -v jq >/dev/null 2>&1; then
        command=$(echo "$json_response" | jq -r '.commands // empty' 2>/dev/null)
        body=$(echo "$json_response" | jq -r '.body // empty' 2>/dev/null)
    else
        # Fallback to sed parsing
        command=$(echo "$json_response" | sed -n 's/.*"commands"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
        body=$(echo "$json_response" | sed -n 's/.*"body"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    fi

    if [ -z "$command" ]; then
        return 0
    fi

    log "Received command from API: $command"

    # Execute command
    case "$command" in
        "KeyChange")
            if [ -z "$body" ]; then
                log "ERROR: KeyChange missing body field"
                log_command "KeyChange FAILED - no body"
                return 1
            fi
            # Unescape JSON if using sed
            if ! command -v jq >/dev/null 2>&1; then
                body=$(echo "$body" | sed 's/\\"/"/g; s/\\\\/\\/g')
            fi
            handle_keychange "$body"
            ;;

        "Restart")
            handle_restart
            ;;

        "Update")
            handle_update "$json_response"
            ;;

        "Shutdown")
            handle_shutdown
            ;;

        *)
            log "WARNING: Unknown command '$command'"
            log_command "Unknown command: $command"
            ;;
    esac
}

# Register device
register_device() {
    local uuid=$(get_uuid)
    local external_ip=$(get_external_ip)
    local internal_ip=$(get_internal_ip)
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    if [ -z "$external_ip" ]; then
        log "WARNING: Failed to get external IP"
    fi

    if [ -z "$internal_ip" ]; then
        log "ERROR: Failed to get internal IP, cannot register"
        return 1
    fi

    local json_payload=$(cat <<EOF
{
    "uuid": "$uuid",
    "external_ip": "$external_ip",
    "internal_ip": "$internal_ip",
    "timestamp": "$timestamp"
}
EOF
)

    log "Attempting registration with UUID: $uuid"
    log "  External IP: ${external_ip:-unavailable}"
    log "  Internal IP: $internal_ip"

    # BYPASS PROXY for API registration
    local response=$(curl --noproxy "*" -s -w "\n%{http_code}" -X POST \
        --max-time 30 \
        -H "Content-Type: application/json" \
        -d "$json_payload" \
        "$REGISTER_ENDPOINT")

    local http_code=$(echo "$response" | tail -1)
    local body=$(echo "$response" | sed '$d')

    if [ "$http_code" = "200" ]; then
        echo "$uuid" > "$KEY_FILE"
        echo "$external_ip|$internal_ip" > "$IP_FILE"
        chmod 600 "$KEY_FILE" "$IP_FILE"
        log "Registration successful, key saved"
        return 0
    else
        log "Registration failed with HTTP $http_code"
        return 1
    fi
}

# Send heartbeat - simplified version
send_heartbeat() {
    local uptime=$(get_uptime)
    local uuid=$(get_uuid)
    local script_version=$(get_script_version)
    local xray_version=$(get_xray_version)
    local architecture=$(get_architecture)
    local xray_status=$(check_xray_service)
    
    # Simple traffic stats
    local traffic=$(get_traffic_stats)

    local json_payload=$(cat <<EOF
{
    "uuid": "$uuid",
    "status": "online",
    "uptime": $uptime,
    "traffic": $traffic,
    "xray_service": "$xray_status",
    "versions": {
        "script": "$script_version",
        "xray": "$xray_version"
    },
    "architecture": "$architecture",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
)

    # BYPASS PROXY for API calls - critical!
    local response=$(curl --noproxy "*" -s -w "\n%{http_code}" -X POST \
        --max-time 30 \
        -H "Content-Type: application/json" \
        -d "$json_payload" \
        "$HEARTBEAT_ENDPOINT")

    local http_code=$(echo "$response" | tail -1)
    local body=$(echo "$response" | sed '$d')

    if [ "$http_code" = "200" ]; then
        log "Heartbeat sent successfully"
        
        # Process any commands from API response
        if [ -n "$body" ] && [ "$body" != "{}" ]; then
            process_commands "$body"
        fi
        return 0
    else
        log "Heartbeat failed with HTTP $http_code"
        return 1
    fi
}

# Check network change - enhanced version
network_changed() {
    local current_external=$(get_external_ip)
    local current_internal=$(get_internal_ip)

    # If no IP file exists, always register
    if [ ! -f "$IP_FILE" ]; then
        log "No IP tracking file found, registration required"
        return 0
    fi

    local last_ips=$(cat "$IP_FILE")
    local last_external=$(echo "$last_ips" | cut -d'|' -f1)
    local last_internal=$(echo "$last_ips" | cut -d'|' -f2)

    # Check for changes
    local changed=false
    if [ "$current_internal" != "$last_internal" ]; then
        log "Internal IP changed: '$last_internal' -> '$current_internal'"
        changed=true
    fi

    if [ "$current_external" != "$last_external" ]; then
        log "External IP changed: '$last_external' -> '$current_external'"
        changed=true
    fi

    # If network changed, reconfigure transparent proxy
    if $changed; then
        log "Network change detected, reconfiguring transparent proxy..."
        if reconfigure_proxy_on_change; then
            log "Transparent proxy reconfigured for new network"
        else
            log "WARNING: Failed to reconfigure transparent proxy for new network"
        fi
        return 0
    fi

    return 1
}

# Show status - simplified version
show_status() {
    echo "=== Libera Agent Status ==="

    # Registration
    if [ -f "$KEY_FILE" ]; then
        echo "✓ Registered: YES"
        echo "  UUID: $(get_uuid)"
        if [ -f "$IP_FILE" ]; then
            local ips=$(cat "$IP_FILE")
            echo "  Last External IP: $(echo "$ips" | cut -d'|' -f1)"
            echo "  Last Internal IP: $(echo "$ips" | cut -d'|' -f2)"
        fi
    else
        echo "✗ Registered: NO"
    fi

    # Current network
    echo ""
    echo "Current Network:"
    detect_network_config >/dev/null 2>&1 || true
    echo "  External IP: $(get_external_ip || echo 'unavailable')"
    echo "  Internal IP: $(get_internal_ip || echo 'unknown')"
    echo "  Interface: ${DEFAULT_IF:-unknown}"
    echo "  Network: ${NETWORK:-unknown}"

    # Services status
    echo ""
    echo "Services:"
    if systemctl is-active --quiet "$SERVICE_NAME.service"; then
        echo "✓ Libera Agent: Running"
    else
        echo "✗ Libera Agent: Stopped"
    fi

    if systemctl is-active --quiet xray.service; then
        echo "✓ Xray: Running ($(get_xray_version))"
    else
        echo "✗ Xray: Stopped"
    fi

    if systemctl is-active --quiet redsocks.service; then
        echo "✓ Redsocks: Running"
    else
        echo "✗ Redsocks: Stopped"
    fi

    # Transparent proxy status
    echo ""
    echo "Transparent Proxy:"
    if iptables -t nat -L XRAY >/dev/null 2>&1; then
        echo "✓ Status: ENABLED"
        echo "  Gateway IP: ${LOCAL_IP:-unknown}"
        echo "  Network: ${NETWORK:-unknown}"

        # Show exclusions
        get_exclusion_ips >/dev/null 2>&1 || true
        echo "  API exclusion: ${API_IP:-unresolved}"
        echo "  VPS exclusion: ${VPS_IP:-not configured}"
        
        # Quick proxy test
        echo -n "  Proxy test: "
        if timeout 3 curl --socks5 127.0.0.1:$PROXY_SOCKS_PORT -s http://www.google.com >/dev/null 2>&1; then
            echo "WORKING"
        else
            echo "FAILED"
        fi
    else
        echo "✗ Status: DISABLED"
    fi

    # Traffic stats
    echo ""
    echo "Traffic Statistics:"
    local traffic=$(get_traffic_stats)
    if command -v jq >/dev/null 2>&1 && [ -n "$traffic" ]; then
        local rx=$(echo "$traffic" | jq -r '.rx_bytes // 0')
        local tx=$(echo "$traffic" | jq -r '.tx_bytes // 0')
        # Convert to human readable
        echo "  RX: $(numfmt --to=iec-i --suffix=B $rx 2>/dev/null || echo "$rx bytes")"
        echo "  TX: $(numfmt --to=iec-i --suffix=B $tx 2>/dev/null || echo "$tx bytes")"
    else
        echo "  $traffic"
    fi

    # System info
    echo ""
    echo "System Info:"
    echo "  Uptime: $(uptime -p 2>/dev/null || echo "$(get_uptime) seconds")"
    echo "  Script Version: $(get_script_version)"
    echo "  Architecture: $(get_architecture)"

    # Recent logs
    echo ""
    echo "Recent logs:"
    tail -5 "$LOG_FILE" 2>/dev/null || echo "No logs"

    echo ""
    echo "Recent commands:"
    tail -5 "$COMMANDS_LOG" 2>/dev/null || echo "No commands"
}

# Uninstall service with log rotation cleanup
uninstall_service() {
    check_root
    echo "Uninstalling Libera agent..."

    # Stop and disable service
    systemctl stop "$SERVICE_NAME.service" 2>/dev/null
    systemctl disable "$SERVICE_NAME.service" 2>/dev/null
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload

    # Remove log rotation
    remove_log_rotation

    # Ask about complete cleanup
    echo "Remove Xray and transparent proxy completely? [y/N]"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        uninstall_everything
    fi

    # Remove script
    rm -f "$SCRIPT_PATH"

    echo "Remove config and log files? [y/N]"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
        rm -f "$LOG_FILE" "$COMMANDS_LOG" "$METRICS_FILE"
        echo "All files removed"
    else
        echo "Config files preserved"
    fi
}

# Main run loop - simplified
run_main_loop() {
    log "Libera agent starting main loop (v$SCRIPT_VERSION)..."

    # Ensure transparent proxy is running if components are installed
    if [ -f "$XRAY_BIN" ] && command -v redsocks >/dev/null 2>&1; then
        if ! iptables -t nat -L XRAY >/dev/null 2>&1; then
            log "Transparent proxy not detected, attempting to set up..."
            if setup_transparent_proxy && start_transparent_proxy_services; then
                log "Transparent proxy initialized successfully"
            else
                log "WARNING: Failed to initialize transparent proxy, continuing anyway"
            fi
        fi
    fi

    while true; do
        # Check registration and network changes
        if [ ! -f "$KEY_FILE" ] || network_changed; then
            log "Registration required"
            if ! register_device; then
                log "Registration failed, retrying in 60 seconds"
                sleep 60
                continue
            fi
        fi

        # Send heartbeat
        send_heartbeat

        # Wait interval
        sleep "$HEARTBEAT_INTERVAL"
    done
}

# Handle arguments
case "${1:-help}" in
    "install"|"setup")
        install_service
        exit 0
        ;;
    "run")
        # This is called by systemd service
        run_main_loop
        ;;
    "uninstall")
        uninstall_service
        exit 0
        ;;
    "uninstall-proxy")
        check_root
        echo "This will remove Xray, redsocks, transparent proxy and clean up all configurations."
        read -p "Are you sure? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            uninstall_everything
        else
            echo "Uninstall cancelled"
        fi
        exit 0
        ;;
    "status")
        show_status
        exit 0
        ;;
    "start")
        systemctl start "$SERVICE_NAME.service"
        exit 0
        ;;
    "stop")
        systemctl stop "$SERVICE_NAME.service"
        exit 0
        ;;
    "logs")
        journalctl -u "$SERVICE_NAME.service" -f
        exit 0
        ;;
    "enable-proxy")
        check_root
        if setup_transparent_proxy && start_transparent_proxy_services; then
            echo "Transparent proxy enabled successfully"
            show_status
        else
            echo "Failed to enable transparent proxy"
            exit 1
        fi
        exit 0
        ;;
    "disable-proxy")
        check_root
        teardown_transparent_proxy
        echo "Transparent proxy disabled successfully"
        exit 0
        ;;
    "version"|"-v"|"--version")
        echo "$SCRIPT_VERSION"
        exit 0
        ;;
    *)
        echo "Libera Agent v$SCRIPT_VERSION - Transparent Proxy Gateway"
        echo ""
        echo "Usage: $0 {install|status|start|stop|logs|version|uninstall}"
        echo ""
        echo "Installation:"
        echo "  install         - Install agent, Xray and transparent proxy"
        echo "  uninstall       - Remove agent service"
        echo "  uninstall-proxy - Remove everything including Xray/proxy"
        echo ""
        echo "Management:"
        echo "  status          - Show service and proxy status"
        echo "  start           - Start agent service"
        echo "  stop            - Stop agent service"
        echo "  logs            - View service logs"
        echo ""
        echo "Proxy Control:"
        echo "  enable-proxy    - Enable transparent proxy manually"
        echo "  disable-proxy   - Disable transparent proxy"
        echo ""
        echo "Info:"
        echo "  version         - Show script version"
        echo ""
        echo "This creates a transparent proxy gateway that routes all network"
        echo "traffic through Xray except API communication and local networks."
        exit 0
        ;;
esac
