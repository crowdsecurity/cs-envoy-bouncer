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
use serde_json;
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

#[derive(Serialize, Deserialize, Debug)]
struct WafResponse {
    action: String,
    #[serde(default)]
    http_status: Option<u16>,
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
        Some(Box::new(CrowdsecFilterHttp::new(
            Rc::clone(&self.bans),
            self.config.clone(),
        )))
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
    request_body: Vec<u8>,
    has_request_body: bool,
    // Cached WAF URL parsing result (cluster, path, authority)
    waf_url_parts: Option<(String, String, String)>,
    // Cached headers for WAF processing
    cached_headers: Option<CachedRequestHeaders>,
}

#[derive(Debug, Clone)]
struct CachedRequestHeaders {
    uri: String,
    host: String,
    method: String,
    user_agent: String,
    request_headers: Vec<(String, String)>,
}

impl CrowdsecFilterHttp {
    fn new(bans: SharedBans, config: FilterConfig) -> Self {
        let waf_url_parts = if config.waf_enabled {
            Self::parse_waf_url_static(&config.waf_url).ok()
        } else {
            None
        };
        
        Self {
            bans,
            config,
            request_body: Vec::new(),
            has_request_body: false,
            waf_url_parts,
            cached_headers: None,
        }
    }

    fn parse_waf_url_static(url: &str) -> Result<(String, String, String), String> {
        // Simple URL parsing for http://host:port/path format
        let without_scheme = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))
            .ok_or("WAF URL must start with http:// or https://")?;
        
        // Split into host_port and path parts
        let (host_port, path) = if let Some(slash_pos) = without_scheme.find('/') {
            (&without_scheme[..slash_pos], &without_scheme[slash_pos..])
        } else {
            (without_scheme, "/")
        };
        
        if host_port.is_empty() {
            return Err("WAF URL missing host".to_string());
        }
        
        // Use the first part (before any colon) as cluster name
        let cluster = if let Some(colon_pos) = host_port.find(':') {
            &host_port[..colon_pos]
        } else {
            host_port
        };
        
        Ok((cluster.to_string(), path.to_string(), host_port.to_string()))
    }

    fn cache_request_headers(&mut self) {
        // Cache headers that will be needed for WAF processing
        let uri = self.get_http_request_header(":path")
            .unwrap_or_else(|| "/".to_string());
        let host = self.get_http_request_header(":authority")
            .or_else(|| self.get_http_request_header("host"))
            .unwrap_or_else(|| "unknown".to_string());
        let method = self.get_http_request_header(":method")
            .unwrap_or_else(|| "GET".to_string());
        let user_agent = self.get_http_request_header("user-agent")
            .unwrap_or_else(|| "unknown".to_string());
        
        // Cache all request headers (excluding pseudo-headers and CrowdSec headers)
        let request_headers = self.get_http_request_headers()
            .into_iter()
            .filter(|(name, _)| !name.starts_with(':') && !name.starts_with("X-Crowdsec-Appsec-"))
            .collect();

        self.cached_headers = Some(CachedRequestHeaders {
            uri,
            host,
            method,
            user_agent,
            request_headers,
        });
    }

    fn send_waf_request(&self, ip_addr: IpAddr, body: Option<&[u8]>) -> Result<u32, String> {
        let headers = self.build_waf_headers(ip_addr, body)?;
        
        // Use cached URL parts
        let (cluster, path, authority) = self.waf_url_parts.as_ref()
            .ok_or("WAF URL not initialized")?;
        
        let timeout = self.config.waf_timeout;

        let log_msg = if let Some(body_data) = body {
            format!("Sending WAF request with body to cluster: {}, path: {}, authority: {} with timeout: {:?}ms, body size: {} bytes", 
                cluster, path, authority, timeout.as_millis(), body_data.len())
        } else {
            format!("Sending WAF request to cluster: {}, path: {}, authority: {} with timeout: {:?}ms", 
                cluster, path, authority, timeout.as_millis())
        };
        proxy_wasm::hostcalls::log(LogLevel::Info, &log_msg).ok();

        // Build header pairs directly with references
        let mut header_pairs = vec![
            (":method", "POST"),
            (":path", path.as_str()),
            (":authority", authority.as_str()),
        ];
        
        // Add custom headers
        let custom_header_pairs: Vec<(&str, &str)> = headers.iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        header_pairs.extend(custom_header_pairs);

        // Log some key headers for debugging
        for (k, v) in &header_pairs {
            if k.starts_with("X-Crowdsec-Appsec-") || k.starts_with(":") {
                proxy_wasm::hostcalls::log(
                    LogLevel::Debug, 
                    &format!("WAF Header: {}: {}", k, v)
                ).ok();
            }
        }

        match self.dispatch_http_call(
            &cluster,
            header_pairs,
            body,
            vec![],
            timeout,
        ) {
            Ok(token_id) => {
                let success_msg = if body.is_some() {
                    format!("dispatch_http_call with body successful, token_id: {}", token_id)
                } else {
                    format!("dispatch_http_call successful, token_id: {}", token_id)
                };
                proxy_wasm::hostcalls::log(LogLevel::Info, &success_msg).ok();
                Ok(token_id)
            },
            Err(e) => {
                let error_msg = format!("Failed to dispatch WAF request: {:?}", e);
                proxy_wasm::hostcalls::log(LogLevel::Error, &error_msg).ok();
                Err(error_msg)
            }
        }
    }

    fn build_waf_headers(&self, ip_addr: IpAddr, body: Option<&[u8]>) -> Result<Vec<(String, String)>, String> {
        let mut headers = Vec::new();

        // Use cached headers when we have a body (body phase), direct access for header-only requests (header phase)
        let (uri, host, method, user_agent, request_headers) = if body.is_some() {
            // Body phase - use cached headers to avoid proxy-wasm access issues
            let cached = self.cached_headers.as_ref()
                .ok_or("Headers not cached - call cache_request_headers() during header phase")?;
            (cached.uri.clone(), cached.host.clone(), cached.method.clone(), 
             cached.user_agent.clone(), cached.request_headers.clone())
        } else {
            // Header phase - can access headers directly
            let uri = self.get_http_request_header(":path")
                .unwrap_or_else(|| "/".to_string());
            let host = self.get_http_request_header(":authority")
                .or_else(|| self.get_http_request_header("host"))
                .unwrap_or_else(|| "unknown".to_string());
            let method = self.get_http_request_header(":method")
                .unwrap_or_else(|| "GET".to_string());
            let user_agent = self.get_http_request_header("user-agent")
                .unwrap_or_else(|| "unknown".to_string());
            
            let request_headers = self.get_http_request_headers()
                .into_iter()
                .filter(|(name, _)| !name.starts_with(':') && !name.starts_with("X-Crowdsec-Appsec-"))
                .collect();
            
            (uri, host, method, user_agent, request_headers)
        };
        
        // Get HTTP version - proxy-wasm doesn't expose this directly, so we'll default to 11
        let http_version = "11".to_string();

        // Convert method to proper case for WAF
        let method_upper = method.to_uppercase();

        // Add required CrowdSec headers
        headers.push(("X-Crowdsec-Appsec-Ip".to_string(), ip_addr.to_string()));
        headers.push(("X-Crowdsec-Appsec-Uri".to_string(), uri));
        headers.push(("X-Crowdsec-Appsec-Host".to_string(), host));
        headers.push(("X-Crowdsec-Appsec-Verb".to_string(), method_upper));
        headers.push(("X-Crowdsec-Appsec-Api-Key".to_string(), self.config.waf_api_key.clone()));
        headers.push(("X-Crowdsec-Appsec-User-Agent".to_string(), user_agent));
        headers.push(("X-Crowdsec-Appsec-Http-Version".to_string(), http_version));

        // Copy original request headers
        for (name, value) in request_headers {
            headers.push((name, value));
        }

        // Set content-type and content-length if we have a body
        if let Some(body_data) = body {
            headers.push(("Content-Length".to_string(), body_data.len().to_string()));
            // Find content-type from the request headers we just processed
            if let Some((_, _content_type)) = headers.iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-type")) {
                // Content-Type already added from request headers, don't duplicate
            } else if body.is_none() {
                // Only try to get content-type directly if we're in header phase
                if let Some(content_type) = self.get_http_request_header("content-type") {
                    headers.push(("Content-Type".to_string(), content_type));
                }
            }
        }

        Ok(headers)
    }

    fn parse_waf_response(&self, response_body: &[u8]) -> Result<WafResponse, String> {
        let response_str = std::str::from_utf8(response_body)
            .map_err(|e| format!("Invalid UTF-8 in WAF response: {}", e))?;
        
        serde_json::from_str::<WafResponse>(response_str)
            .map_err(|e| format!("Failed to parse WAF JSON response: {}", e))
    }
}

impl HttpContext for CrowdsecFilterHttp {
    fn on_http_request_headers(&mut self, _num_headers: usize, end_of_stream: bool) -> Action {
        // Get client IP from Envoy's source address property
        let client_ip = if let Some(addr_bytes) = self.get_property(vec!["source", "address"]) {
            parse_ip_from_bytes(&addr_bytes)
        } else {
            proxy_wasm::hostcalls::log(LogLevel::Info, "Could not get source address").ok();
            None
        };

        // Check if IP is banned
        let is_banned = if let Some(ip_addr) = client_ip {
            self.bans.borrow().contains_direct(ip_addr)
        } else {
            false
        };

        // If IP is banned and we're not configured to forward on decision, block immediately
        if is_banned && !self.config.waf_forward_on_decision {
            proxy_wasm::hostcalls::log(LogLevel::Info, "IP banned").ok();
            self.send_http_response(
                self.config.response_code as u32,
                vec![("content-type", "text/plain")],
                Some(self.config.response_message.as_bytes()),
            );
            return Action::Pause;
        }

        // Check if request has body
        self.has_request_body = !end_of_stream;

        // If WAF is enabled, handle based on whether there's a body
        if self.config.waf_enabled {
            proxy_wasm::hostcalls::log(
                LogLevel::Info, 
                &format!("WAF is enabled, processing request from IP: {:?}", client_ip)
            ).ok();
            
            // Cache headers if we have a body (will need them in body phase)
            if self.has_request_body {
                self.cache_request_headers();
            }
            
            if let Some(ip_addr) = client_ip {
                if !self.has_request_body {
                    // No body, process headers only
                    proxy_wasm::hostcalls::log(
                        LogLevel::Info, 
                        &format!("Forwarding request to WAF (headers only) for IP: {}", ip_addr)
                    ).ok();
                    match self.send_waf_request(ip_addr, None) {
                        Ok(token_id) => {
                            proxy_wasm::hostcalls::log(
                                LogLevel::Info, 
                                &format!("WAF request sent successfully (headers only), token_id: {}", token_id)
                            ).ok();
                            return Action::Pause; // Wait for WAF response
                        }
                        Err(e) => {
                            proxy_wasm::hostcalls::log(
                                LogLevel::Error,
                                &format!("Failed to send WAF headers request: {}", e),
                            ).ok();
                        }
                    }
                } else {
                    // Has body, continue to collect body data
                    proxy_wasm::hostcalls::log(
                        LogLevel::Info, 
                        &format!("Request has body, continuing to collect for IP: {}", ip_addr)
                    ).ok();
                    return Action::Continue;
                }
            } else {
                proxy_wasm::hostcalls::log(LogLevel::Warn, "WAF enabled but no client IP found").ok();
            }
        } else {
            proxy_wasm::hostcalls::log(LogLevel::Debug, "WAF is disabled").ok();
        }

        // If IP is banned but we're configured to forward on decision, still block after WAF
        if is_banned && self.config.waf_forward_on_decision {
            proxy_wasm::hostcalls::log(LogLevel::Info, "IP banned (after WAF check)").ok();
            self.send_http_response(
                self.config.response_code as u32,
                vec![("content-type", "text/plain")],
                Some(self.config.response_message.as_bytes()),
            );
            return Action::Pause;
        }

        Action::Continue
    }

    fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        // Collect body data if WAF is enabled
        if self.config.waf_enabled && self.has_request_body {
            if let Some(body) = self.get_http_request_body(0, body_size) {
                self.request_body.extend_from_slice(&body);
                proxy_wasm::hostcalls::log(
                    LogLevel::Debug, 
                    &format!("Collected {} bytes of body data, total: {}", body.len(), self.request_body.len())
                ).ok();
            }

            // If this is the end of the stream, send complete request to WAF
            if end_of_stream {
                if let Some(addr_bytes) = self.get_property(vec!["source", "address"]) {
                    if let Some(ip_addr) = parse_ip_from_bytes(&addr_bytes) {
                        let body_len = self.request_body.len();
                        proxy_wasm::hostcalls::log(
                            LogLevel::Info, 
                            &format!("Forwarding request to WAF (with body, {} bytes) for IP: {}", body_len, ip_addr)
                        ).ok();
                        // Extract body reference to avoid borrowing conflict
                        let body_ref = &self.request_body;
                        match self.send_waf_request(ip_addr, Some(body_ref)) {
                            Ok(token_id) => {
                                proxy_wasm::hostcalls::log(
                                    LogLevel::Info, 
                                    &format!("WAF request sent successfully (with body), token_id: {}", token_id)
                                ).ok();
                                return Action::Pause; // Wait for WAF response
                            }
                            Err(e) => {
                                proxy_wasm::hostcalls::log(
                                    LogLevel::Error,
                                    &format!("Failed to send WAF body request: {}", e),
                                ).ok();
                            }
                        }
                    }
                }
            }
        }

        Action::Continue
    }

}

impl Context for CrowdsecFilterHttp {
    fn on_http_call_response(&mut self, _token_id: u32, _num_headers: usize, body_size: usize, _num_trailers: usize) {
        proxy_wasm::hostcalls::log(LogLevel::Debug, "Received WAF response").ok();
        
        // Check HTTP status code first
        if let Some(status) = self.get_http_call_response_header(":status") {
            match status.as_str() {
                "200" => {
                    // Request allowed - parse JSON response
                    if body_size > 0 {
                        if let Some(response_body) = self.get_http_call_response_body(0, body_size) {
                            match self.parse_waf_response(&response_body) {
                                Ok(waf_response) => {
                                    match waf_response.action.as_str() {
                                        "allow" => {
                                            proxy_wasm::hostcalls::log(LogLevel::Debug, "WAF allowed request").ok();
                                            self.resume_http_request();
                                            return;
                                        }
                                        "ban" => {
                                            proxy_wasm::hostcalls::log(LogLevel::Info, "WAF banned request").ok();
                                            let status_code = waf_response.http_status.unwrap_or(403);
                                            self.send_http_response(
                                                status_code as u32,
                                                vec![("content-type", "text/plain")],
                                                Some(b"Forbidden: Request blocked by WAF"),
                                            );
                                            return;
                                        }
                                        "captcha" => {
                                            proxy_wasm::hostcalls::log(LogLevel::Info, "WAF requires captcha").ok();
                                            let status_code = waf_response.http_status.unwrap_or(403);
                                            self.send_http_response(
                                                status_code as u32,
                                                vec![("content-type", "text/html")],
                                                Some(b"<html><body>Please complete CAPTCHA verification</body></html>"),
                                            );
                                            return;
                                        }
                                        _ => {
                                            proxy_wasm::hostcalls::log(
                                                LogLevel::Warn, 
                                                &format!("Unknown WAF action: {}", waf_response.action)
                                            ).ok();
                                            self.resume_http_request();
                                            return;
                                        }
                                    }
                                }
                                Err(e) => {
                                    proxy_wasm::hostcalls::log(
                                        LogLevel::Error, 
                                        &format!("Failed to parse WAF response: {}", e)
                                    ).ok();
                                    // Allow request on parse error
                                    self.resume_http_request();
                                    return;
                                }
                            }
                        }
                    }
                    // No body, assume allow
                    self.resume_http_request();
                }
                "403" => {
                    proxy_wasm::hostcalls::log(LogLevel::Info, "WAF returned 403 - blocking request").ok();
                    self.send_http_response(
                        self.config.response_code as u32,
                        vec![("content-type", "text/plain")],
                        Some(self.config.response_message.as_bytes()),
                    );
                }
                "500" => {
                    proxy_wasm::hostcalls::log(LogLevel::Error, "WAF internal error - allowing request").ok();
                    // TODO: Check APPSEC_FAILURE_ACTION config parameter
                    self.resume_http_request();
                }
                "401" => {
                    proxy_wasm::hostcalls::log(LogLevel::Error, "WAF authentication failed - check API key").ok();
                    // Allow request on auth error (could be configured differently)
                    self.resume_http_request();
                }
                _ => {
                    proxy_wasm::hostcalls::log(
                        LogLevel::Warn, 
                        &format!("Unexpected WAF response status: {}", status)
                    ).ok();
                    self.resume_http_request();
                }
            }
        } else {
            proxy_wasm::hostcalls::log(LogLevel::Error, "No status in WAF response").ok();
            self.resume_http_request();
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FilterConfig;

    #[test]
    fn test_waf_url_parsing() {
        // Test basic URL parsing
        let result = CrowdsecFilterHttp::parse_waf_url_static("http://crowdsec_waf/waf").unwrap();
        assert_eq!(result.0, "crowdsec_waf"); // cluster
        assert_eq!(result.1, "/waf"); // path
        assert_eq!(result.2, "crowdsec_waf"); // authority
        
        // Test URL with port
        let result = CrowdsecFilterHttp::parse_waf_url_static("http://crowdsec:7422/waf").unwrap();
        assert_eq!(result.0, "crowdsec"); // cluster (host part only)
        assert_eq!(result.1, "/waf"); // path
        assert_eq!(result.2, "crowdsec:7422"); // authority (host:port)
        
        // Test URL without path
        let result = CrowdsecFilterHttp::parse_waf_url_static("http://waf_service").unwrap();
        assert_eq!(result.0, "waf_service"); // cluster
        assert_eq!(result.1, "/"); // default path
        assert_eq!(result.2, "waf_service"); // authority
        
        // Test URL caching in constructor
        let mut config = FilterConfig::default();
        config.waf_enabled = true;
        config.waf_url = "http://crowdsec_waf/waf".to_string();
        
        let http_context = CrowdsecFilterHttp::new(
            Rc::new(RefCell::new(IpStorage::new())),
            config,
        );
        
        // Verify URL parts were cached
        assert!(http_context.waf_url_parts.is_some());
        let cached_parts = http_context.waf_url_parts.as_ref().unwrap();
        assert_eq!(cached_parts.0, "crowdsec_waf");
        assert_eq!(cached_parts.1, "/waf");
        assert_eq!(cached_parts.2, "crowdsec_waf");
    }
}
