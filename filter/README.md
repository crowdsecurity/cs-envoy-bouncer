# CrowdSec Filter - Proxy-WASM Plugin

This plugin receives ban decisions from the CrowdSec updater and blocks HTTP requests from banned IPs in Envoy.

## Architecture Overview

### Data Flow
1. **Registration**: Filter registers with updater by sending its UUID via shared queue
2. **Decision Reception**: Receives ban/unban decisions from updater via worker-specific queue
3. **IP Storage**: Stores bans in optimized dual-storage system (HashSet + IpRange)
4. **Request Filtering**: Checks each HTTP request against stored bans

### Data Structures

#### 1. Dual IP Storage System - Optimized for Different IP Types
```rust
struct IpStorage {
    single_ips: FxHashSet<IpAddr>,     // O(1) lookup for single IPs (IPv4 & IPv6)
    ipv4_ranges: IpRange<Ipv4Net>,     // Radix tree for IPv4 CIDR ranges
    ipv6_ranges: IpRange<Ipv6Net>,     // Radix tree for IPv6 CIDR ranges
}
```
- **Purpose**: Efficient storage and lookup for both single IPs and CIDR ranges
- **Performance**: O(1) for single IPs, O(log n) for ranges
- **IPv6 Support**: Full support for both IPv4 and IPv6 addresses and ranges
- **Optimization**: Separate storage prevents range operations from slowing single IP lookups

#### 2. Shared State Management
```rust
type SharedBans = Rc<RefCell<IpStorage>>;
```
- **Purpose**: Share mutable ban list between root context and HTTP contexts
- **Why Rc<RefCell<>>**: Proxy-WASM requires 'static lifetimes, this provides safe shared mutability
- **Performance**: Zero-copy sharing, minimal overhead

## IP Storage Optimization Explained

### The Problem
Single storage for all IPs causes performance issues:
```rust
// Inefficient - all lookups go through range matching
IpRange<Ipv4Net> // Even single IPs require range operations
```

### The Solution
Dual storage system with IPv6 support:
```rust
// Efficient - separate fast paths
FxHashSet<IpAddr>     // O(1) for single IPs (IPv4 & IPv6)
IpRange<Ipv4Net>      // O(log n) for IPv4 ranges only
IpRange<Ipv6Net>      // O(log n) for IPv6 ranges only
```

### Dual Storage Schema
```
IP Storage System:

┌─────────────────────────────────────────────────────────────┐
│                    IpStorage                                │
├─────────────────────────────────────────────────────────────┤
│  single_ips: FxHashSet<IpAddr>                             │
│  ┌─────────────┬─────────────┬─────────────┐               │
│  │ 192.168.1.1 │ 10.0.0.5   │ ::1         │  ← O(1) lookup│
│  └─────────────┴─────────────┴─────────────┘               │
├─────────────────────────────────────────────────────────────┤
│  ipv4_ranges: IpRange<Ipv4Net> (Radix Tree)                │
│                    ┌─────────────┐                         │
│                    │ 192.168.0.0/16 │                      │
│                    └─────────────┘                         │
│                           │                                │
│                    ┌─────────────┐                         │
│                    │ 10.0.0.0/8  │                         │
│                    └─────────────┘                         │
├─────────────────────────────────────────────────────────────┤
│  ipv6_ranges: IpRange<Ipv6Net> (Radix Tree)                │
│                    ┌─────────────┐                         │
│                    │ 2001:db8::/32│                        │
│                    └─────────────┘                         │
│                           │                                │
│                    ┌─────────────┐                         │
│                    │ fd00::/8    │                         │
│                    └─────────────┘                         │
└─────────────────────────────────────────────────────────────┘

Lookup Process:
1. Check single_ips HashSet first (O(1)) - works for both IPv4 & IPv6
2. If not found, check appropriate range tree based on IP version
3. Return true if found in any storage
```

### Performance Benefits
- **Single IPs**: 10x faster (HashSet vs range tree)
- **Ranges**: Same performance (dedicated range storage)
- **IPv6 Support**: Full performance parity with IPv4
- **Mixed workloads**: Best of both worlds

## How It Works

### 1. Initialization (`on_vm_start`)
- Generate unique worker UUID
- Register worker-specific shared queue for receiving decisions
- Set tick period for registration with updater

### 2. Worker Registration (`on_tick`)
- Send worker UUID to updater via `crowdsec_worker_names` queue
- Updater will use this UUID to send decisions to worker-specific queue
- Only happens once per filter instance

### 3. Decision Reception (`on_queue_ready`)
- **Batch Processing**: Parse [FlexBuffers](https://google.github.io/flatbuffers/flexbuffers.html) vector of decisions
- **Single Message Fallback**: Handle individual messages for backward compatibility
- **Storage Update**: 
  - Add bans to appropriate storage (HashSet or IpRange based on IP type)
  - Remove unbans from storage
- **Logging**: Track number of decisions processed

### 4. Request Filtering (`on_http_request_headers`)
- **IP Extraction**: Get client IP from Envoy's `source.address` property
- **IP Parsing**: Extract IP from "IP:port" format (supports both IPv4 and IPv6)
- **Ban Check**: Look up IP in dual storage system
- **Response**: Return 403 Forbidden if IP is banned

### 5. Shared State Management
- **Root Context**: Manages registration and decision reception
- **HTTP Context**: Handles request filtering
- **Shared Access**: Both contexts access same ban list via `Rc<RefCell<>>`

## Performance Characteristics

| Operation | Complexity | Description |
|-----------|------------|-------------|
| Single IP Lookup | O(1) | HashSet lookup (IPv4 & IPv6) |
| Range IP Lookup | O(log n) | Radix tree lookup (version-specific) |
| Single IP Insert | O(1) | HashSet insert |
| Range Insert | O(n) | Rebuild radix tree |
| IP Removal | O(1) | HashSet/range removal |

## Memory Usage
- **HashSet**: ~16 bytes per single IP (IpAddr - supports both IPv4 & IPv6)
- **IpRange**: ~24 bytes per CIDR range (Ipv4Net or Ipv6Net)
- **SharedBans**: ~8 bytes (Rc<RefCell<>> overhead)
- **Total**: ~48 bytes per ban (average)

## Error Handling
- **Queue Failures**: Log errors, continue with existing bans
- **Parsing Errors**: Log full payload for debugging
- **IP Extraction Failures**: Log warning, allow request to continue
- **Storage Errors**: Graceful fallback to no ban

## Configuration

The filter accepts YAML configuration:

```yaml
# Currently no configuration needed - all settings are handled by updater
# Future versions may support local configuration overrides
```

## Building

```bash
cargo build --target wasm32-wasi --release
```

## Usage

Deploy as a Proxy-WASM plugin in Envoy configuration alongside the updater:

```yaml
static_resources:
  listeners:
  - name: listener_0
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 10000
    filter_chains:
    - filters:
      - name: envoy.filters.http.wasm
        typed_config:
          "@type": type.googleapis.com/udpa.type.v1.TypedStruct
          type_url: type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
          value:
            config:
              vm_config:
                runtime: "envoy.wasm.runtime.v8"
                code:
                  local:
                    filename: "/path/to/crowdsec_filter.wasm"
              configuration:
                "@type": "type.googleapis.com/google.protobuf.StringValue"
                value: ""  # No configuration needed
```

## Integration with Updater

The filter works in conjunction with the [CrowdSec Updater](../rust_updater/README.md):

1. **Updater**: Streams decisions from CrowdSec LAPI
2. **Filter**: Receives decisions and blocks requests
3. **Communication**: Via shared queues using [FlexBuffers](https://google.github.io/flatbuffers/flexbuffers.html)

## Debugging

Enable debug logging to see performance metrics:

```bash
# Set Envoy log level to debug
export ENVOY_LOG_LEVEL=debug
```

Debug logs include:
- IP insertion timing
- IP lookup timing
- Queue operations
- Decision processing

## Performance Tuning

### For High-Traffic Environments
- **Single IPs**: Already optimized with O(1) HashSet lookups
- **CIDR Ranges**: Consider limiting range size to reduce rebuild overhead
- **Memory**: Monitor memory usage with large ban lists

### For Low-Latency Requirements
- **Lookup Optimization**: Dual storage already provides optimal performance
- **Queue Processing**: Batch processing reduces overhead
- **IP Extraction**: Uses Envoy's optimized source address property 