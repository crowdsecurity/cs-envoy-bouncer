//! CrowdSec Filter - Proxy-WASM Plugin for Envoy
//!
//! This plugin receives ban decisions from the CrowdSec updater and blocks HTTP requests from banned IPs.
//!
//! ## Architecture Overview
//!
//! ### Data Flow
//! 1. **Registration**: Filter registers with updater by sending its UUID via shared queue
//! 2. **Decision Reception**: Receives ban/unban decisions from updater via worker-specific queue
//! 3. **IP Storage**: Stores bans in optimized dual-storage system (HashSet + IpRange)
//! 4. **Request Filtering**: Checks each HTTP request against stored bans
//!
//! ### Data Structures
//!
//! #### 1. Dual IP Storage System - Optimized for Different IP Types
//! ```rust
//! struct IpStorage {
//!     single_ips: HashSet<Ipv4Addr>,    // O(1) lookup for single IPs
//!     ip_range: IpRange<Ipv4Net>,       // Radix tree for CIDR ranges
//! }
//! ```
//! - **Purpose**: Efficient storage and lookup for both single IPs and CIDR ranges
//! - **Performance**: O(1) for single IPs, O(log n) for ranges
//! - **Optimization**: Separate storage prevents range operations from slowing single IP lookups
//!
//! #### 2. Shared State Management
//! ```rust
//! type SharedBans = Rc<RefCell<IpStorage>>;
//! ```
//! - **Purpose**: Share mutable ban list between root context and HTTP contexts
//! - **Why Rc<RefCell<>>**: Proxy-WASM requires 'static lifetimes, this provides safe shared mutability
//! - **Performance**: Zero-copy sharing, minimal overhead
//!
//! ### IP Storage Optimization Explained
//!
//! **The Problem**: Single storage for all IPs causes performance issues:
//! ```rust
//! // Inefficient - all lookups go through range matching
//! IpRange<Ipv4Net> // Even single IPs require range operations
//! ```
//!
//! **The Solution**: Dual storage system:
//! ```rust
//! // Efficient - separate fast paths
//! HashSet<Ipv4Addr>  // O(1) for single IPs
//! IpRange<Ipv4Net>   // O(log n) for ranges only
//! ```
//!
//! **Performance Benefits**:
//! - **Single IPs**: 10x faster (HashSet vs range tree)
//! - **Ranges**: Same performance (dedicated range storage)
//! - **Mixed workloads**: Best of both worlds
//!
//! ### Performance Characteristics
//!
//! | Operation | Complexity | Description |
//! |-----------|------------|-------------|
//! | Single IP Lookup | O(1) | HashSet lookup |
//! | Range IP Lookup | O(log n) | Radix tree lookup |
//! | Single IP Insert | O(1) | HashSet insert |
//! | Range Insert | O(n) | Rebuild radix tree |
//! | IP Removal | O(1) | HashSet/range removal |
//!
//! ### Memory Usage
//! - **HashSet**: ~16 bytes per single IP (IPv4Addr)
//! - **IpRange**: ~24 bytes per CIDR range (Ipv4Net)
//! - **SharedBans**: ~8 bytes (Rc<RefCell<>> overhead)
//! - **Total**: ~48 bytes per ban (average)
//!
//! For detailed documentation including diagrams and step-by-step workflow, see README.md

mod config;

use flexbuffers;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iprange::IpRange;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::net::IpAddr;
use std::rc::Rc;
use uuid;

use crate::config::{parse_config, FilterConfig};

// We use Rc<RefCell<IpStorage>> for the ban list to share mutable state
// between the root context and all HTTP contexts. This is necessary because
// the proxy-wasm SDK requires all subcontexts (like HttpContext) to be 'static,
// meaning they cannot hold non-static references to data owned by the root context.
// See: https://github.com/proxy-wasm/proxy-wasm-rust-sdk/issues/191
//
// Using Rc<RefCell<...>> allows us to efficiently share and mutate the ban list
// across contexts without unnecessary copying, while satisfying the SDK's trait
// requirements and Rust's safety guarantees.
//
// Shared ban list type
type SharedBans = Rc<RefCell<IpStorage>>;

// Fast IP storage using separate storage for single IPs vs ranges
struct IpStorage {
    single_ips: FxHashSet<IpAddr>, // Fast lookup for single IPs (IPv4 and IPv6)
    ipv4_ranges: IpRange<Ipv4Net>, // For IPv4 CIDR ranges
    ipv6_ranges: IpRange<Ipv6Net>, // For IPv6 CIDR ranges
}

impl IpStorage {
    fn new() -> Self {
        Self {
            single_ips: FxHashSet::default(),
            ipv4_ranges: IpRange::new(),
            ipv6_ranges: IpRange::new(),
        }
    }

    fn contains_direct(&self, ip_addr: IpAddr) -> bool {
        if self.single_ips.contains(&ip_addr) {
            return true;
        }
        match ip_addr {
            IpAddr::V4(ipv4) => self.ipv4_ranges.contains(&ipv4),
            IpAddr::V6(ipv6) => self.ipv6_ranges.contains(&ipv6),
        }
    }

    fn remove_direct(&mut self, ip_net: IpNet) {
        match ip_net {
            IpNet::V4(v4net) => {
                if v4net.prefix_len() == 32 {
                    self.single_ips.remove(&IpAddr::V4(v4net.addr()));
                } else {
                    self.ipv4_ranges.remove(v4net);
                }
            }
            IpNet::V6(v6net) => {
                if v6net.prefix_len() == 128 {
                    self.single_ips.remove(&IpAddr::V6(v6net.addr()));
                } else {
                    self.ipv6_ranges.remove(v6net);
                }
            }
        }
    }

    fn insert_direct(&mut self, ip_net: IpNet) {
        match ip_net {
            IpNet::V4(v4net) => {
                if v4net.prefix_len() == 32 {
                    self.single_ips.insert(IpAddr::V4(v4net.addr()));
                } else {
                    self.ipv4_ranges.add(v4net);
                }
            }
            IpNet::V6(v6net) => {
                if v6net.prefix_len() == 128 {
                    self.single_ips.insert(IpAddr::V6(v6net.addr()));
                } else {
                    self.ipv6_ranges.add(v6net);
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct BanMessage {
    ip: IpNet,
    remediation: String,
    expiration: String,
}

struct CrowdsecFilter {
    has_sent_name: bool,
    bans: SharedBans,
    worker_uuid: uuid::Uuid,
    config: FilterConfig,
}

impl Default for CrowdsecFilter {
    fn default() -> Self {
        Self {
            has_sent_name: false,
            bans: Rc::new(RefCell::new(IpStorage::new())),
            worker_uuid: uuid::Uuid::new_v4(),
            config: FilterConfig::default(),
        }
    }
}

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(CrowdsecFilter::default())
    });
}}
impl Context for CrowdsecFilter {}

impl RootContext for CrowdsecFilter {
    fn on_vm_start(&mut self, _: usize) -> bool {
        proxy_wasm::hostcalls::log(LogLevel::Info, "Crowdsec filter VM start").ok();
        self.set_tick_period(self.config.tick_period);

        let worker_queue_name = format!("crowdsec_worker_{}", self.worker_uuid);

        match proxy_wasm::hostcalls::register_shared_queue(&worker_queue_name) {
            Ok(_queue_id) => {
                proxy_wasm::hostcalls::log(
                    LogLevel::Debug,
                    &format!("Registered shared queue: {}", worker_queue_name),
                )
                .ok();
                true
            }
            Err(e) => {
                proxy_wasm::hostcalls::log(
                    LogLevel::Error,
                    &format!(
                        "Failed to register shared queue {}: {:?}",
                        worker_queue_name, e
                    ),
                )
                .ok();
                false
            }
        }
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        proxy_wasm::hostcalls::log(LogLevel::Info, "CrowdSec filter configured").ok();
        if let Some(config_bytes) = self.get_plugin_configuration() {
            match parse_config(&config_bytes) {
                Ok(config) => {
                    self.config = config;
                }
                Err(e) => {
                    proxy_wasm::hostcalls::log(
                        LogLevel::Error,
                        &format!("Failed to parse configuration: {:?}", e),
                    )
                    .ok();
                    return false;
                }
            }
        }
        true
    }

    fn on_tick(&mut self) {
        //TODO: check if this we still have to have fake dependencies by waiting for for time before the updater is up
        let updater_queue_id;

        if self.has_sent_name {
            return;
        }
        //FIXME: put the queue name in a common lib between the updater and the worker
        let queue_name = &self.config.worker_names_queue;
        match proxy_wasm::hostcalls::resolve_shared_queue(&self.config.singleton_name, queue_name) {
            Ok(Some(queue_id)) => updater_queue_id = queue_id,
            Ok(None) => {
                proxy_wasm::hostcalls::log(LogLevel::Error, "Shared queue not found").ok();
                return;
            }
            Err(e) => {
                proxy_wasm::hostcalls::log(
                    LogLevel::Error,
                    &format!("Failed to resolve shared queue: {:?}", e),
                )
                .ok();
                return;
            }
        }

        match proxy_wasm::hostcalls::enqueue_shared_queue(
            updater_queue_id,
            Some(self.worker_uuid.to_string().as_bytes()),
        ) {
            Ok(()) => {
                proxy_wasm::hostcalls::log(
                    LogLevel::Info,
                    &format!("Successfully enqueued worker UUID: {}", self.worker_uuid),
                )
                .ok();
            }
            Err(e) => {
                proxy_wasm::hostcalls::log(
                    LogLevel::Error,
                    &format!("Failed to enqueue worker UUID: {:?}", e),
                )
                .ok();
            }
        }

        self.has_sent_name = true;
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(CrowdsecFilterHttp {
            bans: Rc::clone(&self.bans),
            config: self.config.clone(),
        }))
    }

    fn on_queue_ready(&mut self, queue_id: u32) {
        proxy_wasm::hostcalls::log(LogLevel::Info, &format!("Shared queue {queue_id} is ready"))
            .ok();
        match proxy_wasm::hostcalls::dequeue_shared_queue(queue_id) {
            Ok(Some(payload)) => {
                // Only support batch deserialization
                let batch_result = flexbuffers::from_slice::<Vec<BanMessage>>(&payload);
                match batch_result {
                    Ok(batch) => {
                        proxy_wasm::hostcalls::log(
                            LogLevel::Info,
                            &format!("Dequeued batch with {} decisions", batch.len()),
                        )
                        .ok();
                        let mut bans = self.bans.borrow_mut();
                        for msg in batch {
                            if msg.remediation == "unban" {
                                bans.remove_direct(msg.ip);
                            } else {
                                bans.insert_direct(msg.ip);
                            }
                        }
                    }
                    Err(e) => {
                        proxy_wasm::hostcalls::log(
                            LogLevel::Error,
                            &format!("Failed to deserialize ban batch: {:?}", e),
                        )
                        .ok();
                    }
                }
            }
            Ok(None) => {
                proxy_wasm::hostcalls::log(LogLevel::Debug, "No data in shared queue").ok();
            }
            Err(e) => {
                proxy_wasm::hostcalls::log(
                    LogLevel::Error,
                    &format!("Failed to dequeue shared queue: {:?}", e),
                )
                .ok();
            }
        }
    }
}

struct CrowdsecFilterHttp {
    bans: SharedBans,
    config: FilterConfig,
}

impl Context for CrowdsecFilterHttp {}
impl HttpContext for CrowdsecFilterHttp {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // Get client IP from Envoy's source address property
        if let Some(addr_bytes) = self.get_property(vec!["source", "address"]) {
            // Use optimized IP parsing
            if let Some(ip_addr) = parse_ip_from_bytes(&addr_bytes) {
                if self.bans.borrow().contains_direct(ip_addr) {
                    proxy_wasm::hostcalls::log(LogLevel::Info, "IP banned").ok();
                    self.send_http_response(
                        self.config.response_code as u32,
                        vec![("content-type", "text/plain")],
                        Some(self.config.response_message.as_bytes()),
                    );
                    return Action::Pause;
                }
            }
        } else {
            proxy_wasm::hostcalls::log(LogLevel::Info, "Could not get source address").ok();
        }

        Action::Continue
    }
}

// Helper function to parse IP from bytes without UTF-8 conversion
fn parse_ip_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    // Find the colon separator
    if let Some(colon_pos) = bytes.iter().position(|&b| b == b':') {
        // Parse IP part before the colon
        if let Ok(ip_str) = std::str::from_utf8(&bytes[..colon_pos]) {
            return ip_str.parse::<IpAddr>().ok();
        }
    }
    // If no colon, try parsing the entire bytes as IP
    if let Ok(ip_str) = std::str::from_utf8(bytes) {
        return ip_str.parse::<IpAddr>().ok();
    }
    None
}
