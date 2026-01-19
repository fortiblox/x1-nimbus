#!/bin/bash
#
# X1-Nimbus Installer
# Full Verifying Node for X1 Blockchain
#
# Usage: curl -sSL https://raw.githubusercontent.com/fortiblox/X1-Nimbus/main/install.sh | bash
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
REPO_URL="https://github.com/fortiblox/X1-Nimbus"
INSTALL_DIR="/opt/x1-nimbus"
DATA_DIR="/mnt/x1-nimbus"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/root/.config/x1-nimbus"
CONFIG_FILE="$CONFIG_DIR/config.json"
SERVICE_FILE="/etc/systemd/system/x1-nimbus.service"
VERSION_FILE="$INSTALL_DIR/.version"
GO_VERSION="1.22.5"

# Default settings
DEFAULT_RPC_ENDPOINT="https://rpc.mainnet.x1.xyz"
DEFAULT_RPC_PORT="8899"
DEFAULT_METRICS_PORT="9090"
DEFAULT_LOG_LEVEL="info"
DEFAULT_COMMITMENT="confirmed"

# Print banner
print_banner() {
    echo ""
    echo -e "${CYAN}"
    echo "  +-----------------------------------------------------------------+"
    echo "  |                                                                 |"
    echo "  |     _   _ _           _                                         |"
    echo "  |    | \\ | (_)_ __ ___ | |__  _   _ ___                           |"
    echo "  |    |  \\| | | '_ \` _ \\| '_ \\| | | / __|                          |"
    echo "  |    | |\\  | | | | | | | |_) | |_| \\__ \\                          |"
    echo "  |    |_| \\_|_|_| |_| |_|_.__/ \\__,_|___/                          |"
    echo "  |                                                                 |"
    echo "  |              Full Verifying Node for X1                         |"
    echo "  |                                                                 |"
    echo "  +-----------------------------------------------------------------+"
    echo -e "${NC}"
    echo ""
}

# Logging functions
log_info() { echo -e "${BLUE}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }

print_step() {
    local step=$1
    local total=$2
    local desc=$3
    echo ""
    echo -e "${CYAN}-------------------------------------------------------------------${NC}"
    echo -e "${BOLD}Step ${step}/${total}: ${desc}${NC}"
    echo -e "${CYAN}-------------------------------------------------------------------${NC}"
    echo ""
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        echo "Please run: sudo bash install.sh"
        echo "Or: curl -sSL ... | sudo bash"
        exit 1
    fi
}

# Detect OS and set package manager
detect_os() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot detect OS. Only Linux is supported."
        exit 1
    fi

    source /etc/os-release

    case "$ID" in
        ubuntu|debian)
            PKG_MANAGER="apt-get"
            PKG_UPDATE="apt-get update -qq"
            PKG_INSTALL="apt-get install -y -qq"
            ;;
        centos|rhel|fedora|rocky|almalinux)
            PKG_MANAGER="dnf"
            PKG_UPDATE="dnf check-update || true"
            PKG_INSTALL="dnf install -y -q"
            ;;
        *)
            log_warn "Unsupported OS: $ID. Attempting to continue..."
            PKG_MANAGER="apt-get"
            PKG_UPDATE="apt-get update -qq"
            PKG_INSTALL="apt-get install -y -qq"
            ;;
    esac

    log_success "Detected OS: $PRETTY_NAME"
}

# Check system requirements
check_requirements() {
    local errors=0

    # Check RAM (minimum 2GB, recommend 4GB for full verification)
    local total_ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local total_ram_mb=$((total_ram_kb / 1024))

    if [[ $total_ram_mb -lt 2048 ]]; then
        log_error "Insufficient RAM: ${total_ram_mb}MB (minimum: 2GB)"
        errors=$((errors + 1))
    else
        log_success "RAM: ${total_ram_mb}MB"
    fi

    # Check disk space (minimum 10GB for accounts database)
    local available_gb=$(df -BG /opt 2>/dev/null | tail -1 | awk '{print $4}' | tr -d 'G')
    if [[ -z "$available_gb" || "$available_gb" == "-" ]]; then
        available_gb=$(df -BG / | tail -1 | awk '{print $4}' | tr -d 'G')
    fi

    if [[ $available_gb -lt 10 ]]; then
        log_error "Insufficient disk space: ${available_gb}GB (minimum: 10GB)"
        errors=$((errors + 1))
    else
        log_success "Disk space: ${available_gb}GB available"
    fi

    # Check network connectivity
    if curl -s --connect-timeout 5 https://rpc.mainnet.x1.xyz > /dev/null 2>&1; then
        log_success "Network connectivity: OK"
    else
        log_warn "Cannot reach X1 network. May work once network is available."
    fi

    if [[ $errors -gt 0 ]]; then
        echo ""
        log_error "System does not meet minimum requirements."
        exit 1
    fi
}

# Install system dependencies
install_dependencies() {
    log_info "Updating package lists..."
    $PKG_UPDATE > /dev/null 2>&1

    log_info "Installing dependencies..."
    if [[ "$PKG_MANAGER" == "apt-get" ]]; then
        $PKG_INSTALL build-essential git curl wget jq > /dev/null 2>&1
    else
        $PKG_INSTALL gcc gcc-c++ make git curl wget jq > /dev/null 2>&1
    fi

    log_success "Dependencies installed"
}

# Install Go
install_go() {
    if command -v go &>/dev/null; then
        local current_version=$(go version | awk '{print $3}' | sed 's/go//')
        log_info "Go already installed: $current_version"

        # Check if version is sufficient (1.21+)
        local major=$(echo "$current_version" | cut -d. -f1)
        local minor=$(echo "$current_version" | cut -d. -f2)
        if [[ $major -ge 1 && $minor -ge 21 ]]; then
            log_success "Go version is sufficient"
            return
        fi
    fi

    log_info "Installing Go ${GO_VERSION}..."

    cd /tmp
    local arch=$(uname -m)
    local go_arch="amd64"
    if [[ "$arch" == "aarch64" ]]; then
        go_arch="arm64"
    fi

    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${go_arch}.tar.gz"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "go${GO_VERSION}.linux-${go_arch}.tar.gz"
    rm "go${GO_VERSION}.linux-${go_arch}.tar.gz"

    # Add to PATH for this session
    export PATH=$PATH:/usr/local/go/bin

    # Add to /etc/profile for all users
    if ! grep -q '/usr/local/go/bin' /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi

    log_success "Go ${GO_VERSION} installed"
}

# Create directories
create_directories() {
    log_info "Creating directories..."

    mkdir -p "$INSTALL_DIR"/{bin,scripts,backups}
    mkdir -p "$DATA_DIR"/{accounts,blocks}
    mkdir -p "$CONFIG_DIR"

    log_success "Directories created"
}

# Build from source
build_nimbus() {
    log_info "Building X1-Nimbus..."

    cd "$INSTALL_DIR"

    export PATH=$PATH:/usr/local/go/bin
    go mod tidy > /dev/null 2>&1 || true
    go build -o nimbus ./cmd/nimbus

    # Install binary to bin directory
    mv nimbus "$INSTALL_DIR/bin/"
    chmod +x "$INSTALL_DIR/bin/nimbus"

    # Get version
    VERSION=$("$INSTALL_DIR/bin/nimbus" --version 2>/dev/null | head -1 | awk '{print $2}' || echo "0.1.0")
    echo "$VERSION" > "$VERSION_FILE"

    log_success "Build complete: X1-Nimbus $VERSION"
}

# Create configuration
create_config() {
    log_info "Creating configuration..."

    if [[ ! -f "$CONFIG_FILE" ]]; then
        cat > "$CONFIG_FILE" << EOF
{
    "rpc_endpoint": "$DEFAULT_RPC_ENDPOINT",
    "rpc_server": {
        "enabled": false,
        "port": $DEFAULT_RPC_PORT
    },
    "metrics": {
        "enabled": true,
        "port": $DEFAULT_METRICS_PORT
    },
    "data_dir": "$DATA_DIR",
    "log_level": "$DEFAULT_LOG_LEVEL",
    "commitment": "$DEFAULT_COMMITMENT",
    "verification": {
        "verify_signatures": true,
        "verify_bank_hash": true
    },
    "performance": {
        "poll_interval_ms": 400,
        "buffer_size": 1000,
        "parallel_sig_verify": true
    }
}
EOF
        log_success "Configuration created: $CONFIG_FILE"
    else
        log_warn "Configuration exists, preserving existing settings"
    fi
}

# Install systemd service
install_service() {
    log_info "Installing systemd service..."

    # Parse config for service file
    local rpc_endpoint=$(jq -r '.rpc_endpoint // ""' "$CONFIG_FILE" 2>/dev/null || echo "$DEFAULT_RPC_ENDPOINT")
    local data_dir=$(jq -r '.data_dir // ""' "$CONFIG_FILE" 2>/dev/null || echo "$DATA_DIR")
    local log_level=$(jq -r '.log_level // ""' "$CONFIG_FILE" 2>/dev/null || echo "$DEFAULT_LOG_LEVEL")
    local commitment=$(jq -r '.commitment // ""' "$CONFIG_FILE" 2>/dev/null || echo "$DEFAULT_COMMITMENT")

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=X1-Nimbus Full Verifying Node
Documentation=https://github.com/fortiblox/X1-Nimbus
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$INSTALL_DIR/bin/nimbus \\
    --data-dir=$data_dir \\
    --rpc-endpoint=$rpc_endpoint \\
    --commitment=$commitment \\
    --log-level=$log_level \\
    --stats
Restart=always
RestartSec=10
LimitNOFILE=65535
LimitNPROC=65535

# Memory limits (adjust based on available RAM)
MemoryMax=8G
MemoryHigh=6G

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=x1-nimbus

# Security hardening
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Systemd service installed"
}

# Install wrapper script
install_wrapper() {
    log_info "Installing x1-nimbus command..."

    cat > "$BIN_DIR/x1-nimbus" << 'WRAPPER_EOF'
#!/bin/bash
#
# X1-Nimbus Management Wrapper
# https://github.com/fortiblox/X1-Nimbus
#

INSTALL_DIR="/opt/x1-nimbus"
CONFIG_DIR="/root/.config/x1-nimbus"
CONFIG_FILE="$CONFIG_DIR/config.json"
DATA_DIR="/mnt/x1-nimbus"
SERVICE_NAME="x1-nimbus"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

show_help() {
    echo -e "${CYAN}+-----------------------------------------------------------------+${NC}"
    echo -e "${CYAN}|${NC}     ${WHITE}X1-Nimbus - Full Verifying Node${NC}                             ${CYAN}|${NC}"
    echo -e "${CYAN}+-----------------------------------------------------------------+${NC}"
    echo ""
    echo "Usage: x1-nimbus <command> [options]"
    echo ""
    echo -e "${WHITE}Service Commands:${NC}"
    echo "  start           Start the X1-Nimbus service"
    echo "  stop            Stop the X1-Nimbus service"
    echo "  restart         Restart the X1-Nimbus service"
    echo "  status          Show service status and health"
    echo ""
    echo -e "${WHITE}Monitoring Commands:${NC}"
    echo "  logs [lines]    Show recent logs (default: 50 lines)"
    echo "  follow          Follow logs in real-time"
    echo "  stats           Show verification statistics"
    echo ""
    echo -e "${WHITE}Configuration Commands:${NC}"
    echo "  config          Show current configuration"
    echo "  config edit     Edit configuration file"
    echo "  version         Show version information"
    echo "  uninstall       Uninstall X1-Nimbus"
    echo ""
    echo "Examples:"
    echo "  x1-nimbus start"
    echo "  x1-nimbus logs 100"
    echo "  x1-nimbus config edit"
}

cmd_start() {
    echo -e "${BLUE}[*]${NC} Starting X1-Nimbus..."
    systemctl start $SERVICE_NAME
    sleep 3
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo -e "${GREEN}[+]${NC} X1-Nimbus started successfully"
        echo ""
        cmd_status
    else
        echo -e "${RED}[-]${NC} Failed to start X1-Nimbus"
        echo "Check logs: x1-nimbus logs"
        exit 1
    fi
}

cmd_stop() {
    echo -e "${BLUE}[*]${NC} Stopping X1-Nimbus..."
    systemctl stop $SERVICE_NAME
    echo -e "${GREEN}[+]${NC} X1-Nimbus stopped"
}

cmd_restart() {
    echo -e "${BLUE}[*]${NC} Restarting X1-Nimbus..."
    systemctl restart $SERVICE_NAME
    sleep 3
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo -e "${GREEN}[+]${NC} X1-Nimbus restarted successfully"
    else
        echo -e "${RED}[-]${NC} Failed to restart X1-Nimbus"
        exit 1
    fi
}

cmd_status() {
    echo -e "${CYAN}-------------------------------------------------------------------${NC}"
    echo -e "${CYAN}                    X1-Nimbus Status                               ${NC}"
    echo -e "${CYAN}-------------------------------------------------------------------${NC}"
    echo ""

    # Service status
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo -e "Service:     ${GREEN}* Running${NC}"
    else
        echo -e "Service:     ${RED}* Stopped${NC}"
    fi

    # Version
    VERSION=$(cat "$INSTALL_DIR/.version" 2>/dev/null || echo "unknown")
    echo -e "Version:     ${WHITE}$VERSION${NC}"

    # Uptime
    if systemctl is-active --quiet $SERVICE_NAME; then
        UPTIME=$(systemctl show $SERVICE_NAME --property=ActiveEnterTimestamp | cut -d'=' -f2)
        echo -e "Started:     ${WHITE}$UPTIME${NC}"

        # Memory usage
        PID=$(systemctl show $SERVICE_NAME --property=MainPID | cut -d'=' -f2)
        if [[ "$PID" != "0" && -n "$PID" ]]; then
            MEM=$(ps -p $PID -o rss= 2>/dev/null | awk '{printf "%.1f MB", $1/1024}')
            echo -e "Memory:      ${WHITE}$MEM${NC}"
        fi
    fi

    # Config summary
    echo ""
    echo -e "${YELLOW}Configuration:${NC}"
    if [[ -f "$CONFIG_FILE" ]]; then
        local commitment=$(jq -r '.commitment // "confirmed"' "$CONFIG_FILE" 2>/dev/null)
        local verify_sig=$(jq -r '.verification.verify_signatures // true' "$CONFIG_FILE" 2>/dev/null)
        local verify_bank=$(jq -r '.verification.verify_bank_hash // true' "$CONFIG_FILE" 2>/dev/null)
        echo -e "  Commitment:        ${WHITE}$commitment${NC}"
        echo -e "  Verify Signatures: ${WHITE}$verify_sig${NC}"
        echo -e "  Verify Bank Hash:  ${WHITE}$verify_bank${NC}"
    fi

    # Latest activity
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo ""
        echo -e "${YELLOW}Latest activity:${NC}"
        journalctl -u $SERVICE_NAME -n 5 --no-pager --output=short 2>/dev/null | tail -5 || echo "No logs available"
    fi

    echo ""
    echo -e "${CYAN}-------------------------------------------------------------------${NC}"
}

cmd_logs() {
    LINES=${1:-50}
    journalctl -u $SERVICE_NAME -n $LINES --no-pager
}

cmd_follow() {
    echo -e "${CYAN}Following X1-Nimbus logs (Ctrl+C to stop)...${NC}"
    echo ""
    journalctl -u $SERVICE_NAME -f
}

cmd_stats() {
    echo -e "${CYAN}-------------------------------------------------------------------${NC}"
    echo -e "${CYAN}                Verification Statistics                            ${NC}"
    echo -e "${CYAN}-------------------------------------------------------------------${NC}"
    echo ""

    # Parse recent logs for statistics
    journalctl -u $SERVICE_NAME -n 100 --no-pager 2>/dev/null | grep -E "(Blocks verified|Transactions|Signatures)" | tail -10

    echo ""
    echo -e "${CYAN}-------------------------------------------------------------------${NC}"
}

cmd_config() {
    if [[ "$1" == "edit" ]]; then
        ${EDITOR:-nano} "$CONFIG_FILE"
        echo ""
        echo -e "${YELLOW}[!]${NC} Restart required to apply changes: x1-nimbus restart"
    else
        echo -e "${CYAN}-------------------------------------------------------------------${NC}"
        echo -e "${CYAN}                Current Configuration                              ${NC}"
        echo -e "${CYAN}-------------------------------------------------------------------${NC}"
        echo ""
        if [[ -f "$CONFIG_FILE" ]]; then
            jq . "$CONFIG_FILE" 2>/dev/null || cat "$CONFIG_FILE"
        else
            echo "No configuration file found at: $CONFIG_FILE"
        fi
        echo ""
        echo -e "${CYAN}-------------------------------------------------------------------${NC}"
        echo ""
        echo "To edit: x1-nimbus config edit"
    fi
}

cmd_version() {
    VERSION=$(cat "$INSTALL_DIR/.version" 2>/dev/null || echo "unknown")
    COMMIT="unknown"
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        COMMIT=$(cd "$INSTALL_DIR" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    fi
    echo "X1-Nimbus $VERSION ($COMMIT)"
}

cmd_uninstall() {
    echo -e "${YELLOW}+-----------------------------------------------------------------+${NC}"
    echo -e "${YELLOW}|              Uninstall X1-Nimbus                                |${NC}"
    echo -e "${YELLOW}+-----------------------------------------------------------------+${NC}"
    echo ""
    echo "This will remove:"
    echo "  - X1-Nimbus binary ($INSTALL_DIR)"
    echo "  - Systemd service"
    echo "  - Configuration files ($CONFIG_DIR)"
    echo "  - Wrapper commands"
    echo ""
    echo -e "${RED}Data directory ($DATA_DIR) will NOT be removed.${NC}"
    echo ""

    read -p "Are you sure you want to uninstall? [y/N] " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}[*]${NC} Stopping service..."
        systemctl stop $SERVICE_NAME 2>/dev/null || true
        systemctl disable $SERVICE_NAME 2>/dev/null || true

        echo -e "${BLUE}[*]${NC} Removing files..."
        rm -f /etc/systemd/system/x1-nimbus.service
        rm -f /usr/local/bin/x1-nimbus
        rm -rf "$INSTALL_DIR"
        rm -rf "$CONFIG_DIR"

        systemctl daemon-reload

        echo ""
        echo -e "${GREEN}[+]${NC} X1-Nimbus uninstalled"
        echo ""
        echo "Data directory preserved at: $DATA_DIR"
        echo "To remove data: rm -rf $DATA_DIR"
    else
        echo "Uninstall cancelled"
    fi
}

# Main command router
case "${1:-help}" in
    start)      cmd_start ;;
    stop)       cmd_stop ;;
    restart)    cmd_restart ;;
    status)     cmd_status ;;
    logs)       cmd_logs "$2" ;;
    follow)     cmd_follow ;;
    stats)      cmd_stats ;;
    config)     cmd_config "$2" ;;
    version)    cmd_version ;;
    uninstall)  cmd_uninstall ;;
    help|--help|-h) show_help ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        echo ""
        show_help
        exit 1
        ;;
esac
WRAPPER_EOF

    chmod +x "$BIN_DIR/x1-nimbus"
    log_success "x1-nimbus command installed"
}

# Enable and start service
start_service() {
    log_info "Starting X1-Nimbus..."

    systemctl enable x1-nimbus > /dev/null 2>&1
    systemctl start x1-nimbus

    sleep 5

    if systemctl is-active --quiet x1-nimbus; then
        log_success "X1-Nimbus is running"
    else
        log_warn "Service may still be starting. Check: x1-nimbus status"
    fi
}

# Print completion message
print_complete() {
    echo ""
    echo -e "${GREEN}+-----------------------------------------------------------------+${NC}"
    echo -e "${GREEN}|                                                                 |${NC}"
    echo -e "${GREEN}|          Installation Complete!                                 |${NC}"
    echo -e "${GREEN}|                                                                 |${NC}"
    echo -e "${GREEN}+-----------------------------------------------------------------+${NC}"
    echo ""
    echo "X1-Nimbus is now running as a full verifying node."
    echo "It independently validates every transaction using:"
    echo "  - Ed25519 signature verification"
    echo "  - Transaction execution via SVM"
    echo "  - Bank hash computation and verification"
    echo ""
    echo -e "${WHITE}Quick Commands:${NC}"
    echo "  x1-nimbus status    - Check service status"
    echo "  x1-nimbus logs      - View recent logs"
    echo "  x1-nimbus follow    - Follow logs in real-time"
    echo "  x1-nimbus stats     - Show verification statistics"
    echo "  x1-nimbus config    - View configuration"
    echo "  x1-nimbus help      - Show all commands"
    echo ""
    echo -e "${WHITE}File Locations:${NC}"
    echo "  Binary:      $INSTALL_DIR/bin/nimbus"
    echo "  Config:      $CONFIG_FILE"
    echo "  Data:        $DATA_DIR"
    echo "  Logs:        journalctl -u x1-nimbus"
    echo ""
    echo -e "${CYAN}Thank you for running X1-Nimbus!${NC}"
    echo ""
}

# Main installation flow
main() {
    print_banner

    echo -e "${BOLD}X1-Nimbus Installer${NC}"
    echo ""
    echo "This will install the X1-Nimbus full verifying node."
    echo "Unlike X1-Stratus, X1-Nimbus independently validates every"
    echo "transaction without trusting any third party."
    echo ""
    echo "Features:"
    echo "  - Ed25519 signature verification"
    echo "  - Full transaction execution via SVM"
    echo "  - Bank hash computation and verification"
    echo "  - RPC-based block streaming"
    echo ""

    read -p "Continue with installation? [Y/n] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]?$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi

    local total_steps=8

    print_step 1 $total_steps "Checking prerequisites"
    check_root
    detect_os
    check_requirements

    print_step 2 $total_steps "Installing dependencies"
    install_dependencies

    print_step 3 $total_steps "Installing Go"
    install_go

    print_step 4 $total_steps "Creating directories"
    create_directories

    print_step 5 $total_steps "Building X1-Nimbus"
    build_nimbus

    print_step 6 $total_steps "Creating configuration"
    create_config

    print_step 7 $total_steps "Installing service"
    install_service
    install_wrapper

    print_step 8 $total_steps "Starting service"
    start_service

    print_complete
}

# Run main
main "$@"
