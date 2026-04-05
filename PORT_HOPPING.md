# Port Hopping Feature for ShadowQuic

## Overview

This document describes the port hopping feature added to shadowquic to help evade UDP blocking and port-based traffic classification.

## How It Works

1. **Configuration**: Add `port-hop-interval` and `port-hop-server-ports` in client config
2. **Timer**: A background timer runs with random intervals (5s ~ max_interval)
3. **Hop Trigger**: When timer fires, the client:
   - Closes the existing QUIC connection
   - Connects to a new random port within the configured server port range

## Configuration

### Client Configuration

Edit `config_examples/client.yaml`:

```yaml
inbound:
    type: socks
    bind-addr: "127.0.0.1:1089"
outbound:
    type: shadowquic
    addr: "YOUR_SERVER_IP:1443"
    username: "87654321"
    password: "12345678"
    server-name: "cloudflare.com"
    alpn: ["h3"]
    zero-rtt: true
    # Port hopping configuration
    port-hop-interval: 10  # Max interval in seconds
    port-hop-server-ports: "50000-60000"  # Server port range
log-level: "info"
```

### Server Configuration (iptables)

On the server, set up iptables to redirect multiple ports to the shadowquic listening port:

```bash
# Example: Map ports 50000-60000 to internal port 1443
sudo ./scripts/setup_port_mapping.sh 50000 60000 1443
```

Or manually:

```bash
# Create independent chain
sudo iptables -t nat -N SHADOWQUIC-HOP

# Add DNAT rules
for port in $(seq 50000 60000); do
    sudo iptables -t nat -A SHADOWQUIC-HOP -p udp --dport $port -j DNAT --to-destination :1443
done

# Insert PREROUTING rule
sudo iptables -t nat -I PREROUTING 1 -p udp --dport 50000:60000 -j SHADOWQUIC-HOP

# For local delivery (if server is on the same machine)
sudo iptables -t nat -I OUTPUT 1 -p udp --dport 50000:60000 -j SHADOWQUIC-HOP
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `port-hop-interval` | u64 | 0 (disabled) | Maximum hop interval in seconds. If < 5, uses fixed 5s. If >= 5, uses random between 5s and this value. |
| `port-hop-server-ports` | String | None | Server port range for hopping, format "start-end". Required when port-hop-interval > 0. |

## Timing Details

- **Minimum interval**: 5 seconds (fixed)
- **Maximum interval**: `port-hop-interval` seconds
- **Logic**:
  - If `port-hop-interval < 5`: uses fixed 5 second interval
  - If `port-hop-interval >= 5`: uses random between 5s and `port-hop-interval` seconds

Example: If `port-hop-interval: 10`, actual intervals could be: 5s, 7s, 8s, 10s, 12s, etc.

Example: If `port-hop-interval: 3`, actual intervals will always be: 5s (fixed)

## Pros and Cons

### Advantages

1. **Evades port-based blocking**: ISP or firewall rules targeting specific UDP ports become ineffective
2. **Traffic analysis resistance**: Makes it harder to identify and classify the traffic pattern
3. **Zero server modification**: Server only needs iptables/nftables port mapping

### Disadvantages

1. **Connection interruption**: Brief connection disruption during port hop (mitigated by 0-RTT)
2. **Increased latency**: Each hop requires new QUIC handshake
3. **Port exhaustion risk**: Very frequent hopping could exhaust ephemeral ports (mitigated by 5s minimum)

## Recommendation

- Use `port-hop-interval: 10` for moderate protection
- Use `port-hop-interval: 30-60` for stronger protection
- Always enable `zero-rtt: true` to minimize reconnection time
- Ensure server has sufficient port range mapped (1000+ ports recommended)

## Implementation Details

The port hopping implementation follows these principles:

1. **Non-blocking hop**: The hop timer runs in background, setting a flag when hop is needed
2. **Random port selection**: Client randomly selects a port from the configured server port range
3. **Minimal overhead**: Uses atomic flag for signaling, minimal allocations
4. **Graceful shutdown**: Uses watch channel for clean timer termination
5. **Concurrent safety**: RwLock protects hop state for better read concurrency

## Files Modified

1. `shadowquic/src/config/shadowquic.rs` - Added `port_hop_interval` and `port_hop_server_ports` config fields
2. `shadowquic/src/shadowquic/outbound.rs` - Implemented port hopping logic
3. `shadowquic/Cargo.toml` - Added `rand` dependency
4. `shadowquic/config_examples/client.yaml` - Updated example config
5. `shadowquic/scripts/setup_port_mapping.sh` - Added server port mapping script
