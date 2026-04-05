#!/bin/bash
# Port mapping script for shadowquic server with port hopping support
# This script sets up iptables rules to map multiple UDP ports to the shadowquic server
# Usage: ./setup_port_mapping.sh <start_port> <end_port> <server_port>
# Example: ./setup_port_mapping.sh 50000 60000 1443

# Default values
START_PORT=${1:-50000}
END_PORT=${2:-60000}
SERVER_PORT=${3:-1443}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root (use sudo)"
   exit 1
fi

# Backup existing rules
BACKUP_FILE="/tmp/iptables.shadowquic.backup.$(date +%Y%m%d_%H%M%S)"
log_info "Backing up existing iptables NAT rules..."
iptables-save > "$BACKUP_FILE" 2>/dev/null || true

# Create a new chain for shadowquic port hopping
log_info "Creating shadowquic-hop chain..."
iptables -t nat -N SHADOWQUIC-HOP 2>/dev/null || {
    log_warn "Chain already exists, clearing it..."
    iptables -t nat -F SHADOWQUIC-HOP
}

# Add DNAT rules for each port in the range
log_info "Adding DNAT rules for ports $START_PORT-$END_PORT -> $SERVER_PORT..."
for ((port=START_PORT; port<=END_PORT; port++)); do
    iptables -t nat -A SHADOWQUIC-HOP -p udp --dport $port -j DNAT --to-destination :$SERVER_PORT
done

# Insert rule at the beginning of PREROUTING chain
log_info "Inserting rule into PREROUTING chain..."
iptables -t nat -I PREROUTING 1 -p udp --dport $START_PORT:$END_PORT -j SHADOWQUIC-HOP

# For local delivery (if server is on the same machine)
log_info "Adding OUTPUT chain rule for local delivery..."
iptables -t nat -I OUTPUT 1 -p udp --dport $START_PORT:$END_PORT -j SHADOWQUIC-HOP

echo ""
log_info "Port mapping setup complete!"
echo ""
echo "Configuration:"
echo "  - External ports: $START_PORT - $END_PORT"
echo "  - Internal port:  $SERVER_PORT"
echo "  - Total ports:    $((END_PORT - START_PORT + 1))"
echo ""
echo "Current NAT rules:"
iptables -t nat -L PREROUTING -n | grep -E "(SHADOWQUIC|Chain)" | head -20
echo ""
echo "Backup saved to: $BACKUP_FILE"
echo ""
log_warn "Note: Make sure shadowquic is configured to accept connections on 0.0.0.0:$SERVER_PORT"
echo ""
echo "To remove the rules:"
echo "  sudo iptables -t nat -F SHADOWQUIC-HOP"
echo "  sudo iptables -t nat -X SHADOWQUIC-HOP"
echo "  sudo iptables -t nat -D PREROUTING -p udp --dport $START_PORT:$END_PORT -j SHADOWQUIC-HOP"
echo "  sudo iptables -t nat -D OUTPUT -p udp --dport $START_PORT:$END_PORT -j SHADOWQUIC-HOP"
