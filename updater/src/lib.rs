//! CrowdSec Updater - Proxy-WASM Plugin for Envoy
//!
//! This plugin streams decisions from CrowdSec LAPI and distributes them to multiple filter instances.
//!
//! ## Architecture Overview
//!
//! ### Data Flow
//! 1. **LAPI Streaming**: We stream decisions from CrowdSec LAPI using the `/v1/decisions/stream` endpoint
//! 2. **Decision Processing**: Parse incoming decisions and store them in optimized data structures
//! 3. **Distribution**: Send decisions to all connected filter instances via shared queues
//!
//! ### Data Structures
//!
//! #### 1. BanMessage HashMap - O(1) Fast Lookup
//! ```rust
//! HashMap<IpNet, BanMessage> // IpNet -> ban information
//! ```
//! - **Purpose**: Fast IP lookup for checking if an IP is banned
//! - **Performance**: O(1) average case for insertions and lookups
//! - **Contains**: IP (as IpNet), remediation type, and expiration string
//! - **IPv6 Support**: Full support for both IPv4 and IPv6 addresses and ranges
//!
//! #### 2. BinaryHeap Priority Queue - O(log n) Expiration Management
//! ```rust
//! BinaryHeap<Reverse<ExpirationEntry>> // Priority queue for expiration times
//! ```
//! - **Purpose**: Efficiently track and process expiring bans (fallback mode only)
//! - **Performance**: O(1) to check next expiration, O(log n) to add/remove
//! - **Optimization**: Only checks the next expiring ban instead of scanning all bans
//! - **Memory**: Stores IpNet directly for simplicity and reliability
//! - **Hybrid**: Only active when LAPI is unavailable (local fallback)
//!
//! #### 3. Batch Removal Tracking
//! ```rust
//! HashSet<IpNet> // Track IPNets to remove for lazy cleanup
//! ```
//! - **Purpose**: Efficiently handle multiple deletions without rebuilding queue on each removal
//! - **Performance**: O(1) marking, O(k) batch rebuild where k = queue size
//! - **Optimization**: Batch rebuild instead of individual removals
//!
//! ### Performance Characteristics
//!
//! | Operation | Complexity | Description |
//! |-----------|------------|-------------|
//! | IP Lookup | O(1) | HashMap lookup |
//! | Add Ban | O(log n) | HashMap insert + BinaryHeap insert |
//! | Remove Ban | O(1) | Mark for removal (batch rebuild) |
//! | Check Expiration | O(1) | BinaryHeap peek |
//! | Process Expired | O(k log n) | Where k = number of expired bans |
//! | Batch Rebuild | O(k) | Rebuild queue once after all deletions |
//!
//! For detailed documentation including diagrams and step-by-step workflow, see README.md

mod config;
mod core;

use ipnet::IpNet;
use log::info;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::SystemTime;

use crate::config::{parse_config, UpdaterConfig};
use crate::core::{
    build_query_params, parse_expiration, parse_ip_with_cidr, send_batched, BanMessage,
    ExpirationEntry, StreamResponse,
};

struct CrowdsecUpdater {
    // Core data structures
    bans: HashMap<IpNet, BanMessage>, // IpNet -> ban message
    expiration_queue: BinaryHeap<Reverse<ExpirationEntry>>, // Priority queue for expirations
    ips_to_remove: HashSet<IpNet>,    // Track IPNets to remove for lazy cleanup

    // Configuration
    config: UpdaterConfig,
    is_startup: bool,
    worker_names_queue_id: Option<u32>,
    worker_queues_ids: Vec<u32>,
}

impl Default for CrowdsecUpdater {
    fn default() -> Self {
        Self {
            // Core data structures
            bans: HashMap::new(),
            expiration_queue: BinaryHeap::new(),
            ips_to_remove: HashSet::new(),

            // Configuration
            config: UpdaterConfig::default(),
            is_startup: true,
            worker_names_queue_id: None,
            worker_queues_ids: vec![],
        }
    }
}

const STR_WORKER_NAMES_QUEUE: &str = "crowdsec_worker_names";

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(CrowdsecUpdater::default()) });
}}

impl CrowdsecUpdater {
    fn broadcast_decisions(&self, decisions: &[BanMessage]) {
        let batches = match send_batched(decisions, self.config.batch_size, self.config.max_batch_bytes) {
            Ok(batches) => batches,
            Err(e) => {
                proxy_wasm::hostcalls::log(
                    LogLevel::Error,
                    &format!("Failed to batch decisions: {}", e),
                )
                .ok();
                return;
            }
        };

        for batch in batches {
            let batch_bytes = match flexbuffers::to_vec(&batch) {
                Ok(bytes) => bytes,
                Err(e) => {
                    proxy_wasm::hostcalls::log(
                        LogLevel::Error,
                        &format!("Failed to serialize batch: {}", e),
                    )
                    .ok();
                    continue;
                }
            };

            for &queue_id in &self.worker_queues_ids {
                if let Err(e) =
                    proxy_wasm::hostcalls::enqueue_shared_queue(queue_id, Some(&batch_bytes))
                {
                    proxy_wasm::hostcalls::log(
                        LogLevel::Error,
                        &format!("Failed to enqueue to worker queue {}: {:?}", queue_id, e),
                    )
                    .ok();
                }
            }
        }
    }

    fn check_expired_bans(&mut self) -> Vec<BanMessage> {
        // Clean up any marked IPs before checking expirations
        self.cleanup_expiration_queue();

        let now = SystemTime::now();
        let mut unban_messages = Vec::new();

        while let Some(Reverse(ExpirationEntry { expiration, ip })) = self.expiration_queue.peek() {
            if now >= *expiration {
                if let Some(ban_msg) = self.bans.remove(ip) {
                    // Create unban message using the stored IpNet
                    let msg = BanMessage {
                        ip: ban_msg.ip,
                        remediation: "unban".to_string(),
                        expiration: ban_msg.expiration,
                    };
                    unban_messages.push(msg);
                }
                self.expiration_queue.pop();
            } else {
                break;
            }
        }

        unban_messages
    }

    fn remove_from_expiration_queue(&mut self, ip: &IpNet) {
        // O(1) - just mark for removal, cleanup happens later
        self.ips_to_remove.insert(*ip);
    }

    fn add_to_expiration_queue(&mut self, ip: &IpNet, expiration: SystemTime) {
        self.expiration_queue.push(Reverse(ExpirationEntry {
            expiration,
            ip: *ip,
        }));
    }

    fn cleanup_expiration_queue(&mut self) {
        // Only rebuild when we have IPs to remove
        if self.ips_to_remove.is_empty() {
            return;
        }

        // Rebuild queue without the marked IPs - O(k) where k = queue size
        let mut new_queue = BinaryHeap::new();
        while let Some(Reverse(entry)) = self.expiration_queue.pop() {
            if !self.ips_to_remove.contains(&entry.ip) {
                new_queue.push(Reverse(entry));
            }
        }
        self.expiration_queue = new_queue;
        self.ips_to_remove.clear();
    }

    fn log(&self, level: LogLevel, message: &str) {
        proxy_wasm::hostcalls::log(level, &format!("[CrowdSec Updater] {}", message)).ok();
    }

    fn poll_lapi(&mut self) {
        // Check for expired bans first (if LAPI failed in previous tick)
        // This will be called from on_http_call_response if LAPI fails

        if self.worker_queues_ids.is_empty() {
            proxy_wasm::hostcalls::log(LogLevel::Error, "Worker queues not initialized").ok();
            return;
        }

        let mut path = "/v1/decisions/stream".to_string();

        // Build query parameters using core module
        let query_params = build_query_params(
            self.is_startup,
            &self.config.scopes,
            &self.config.origins,
            &self.config.scenarios_containing,
            &self.config.scenarios_not_containing,
        );
        if !query_params.is_empty() {
            path = format!("{}{}", path, query_params);
        }

        self.is_startup = false;

        let headers = vec![
            (":method", "GET"),
            (":path", &path),
            (":authority", "crowdsec"),
            ("x-api-key", &self.config.api_key),
        ];

        info!("Asking the crowdsec LAPI for decisions {path}");

        match self.dispatch_http_call(
            &self.config.cluster_name,
            headers,
            None,
            vec![],
            self.config.lapi_timeout,
        ) {
            Ok(_) => {
                proxy_wasm::hostcalls::log(
                    LogLevel::Debug,
                    "LAPI call dispatched successfully",
                )
                .ok();
            }
            Err(e) => {
                proxy_wasm::hostcalls::log(
                    LogLevel::Error,
                    &format!("Failed to dispatch LAPI call: {:?}", e),
                )
                .ok();
                // LAPI call failed - run local expiration
                let unban_messages = self.check_expired_bans();
                if !unban_messages.is_empty() {
                    self.broadcast_decisions(&unban_messages);
                    proxy_wasm::hostcalls::log(
                        LogLevel::Info,
                        &format!("Removed {} expired bans", unban_messages.len()),
                    )
                    .ok();
                }
            }
        }
    }

    fn handle_lapi_response(&mut self) {
        // Check if LAPI call was successful
        let is_success = self
            .get_http_call_response_header(":status")
            .map(|status| status == "200")
            .unwrap_or(false);

        if !is_success {
            // LAPI call failed - run local expiration
            let status_msg = self
                .get_http_call_response_header(":status")
                .map(|s| format!("with status: {}", s))
                .unwrap_or_else(|| "no status code".to_string());
            proxy_wasm::hostcalls::log(LogLevel::Warn, &format!("LAPI call failed {}", status_msg))
                .ok();

            let unban_messages = self.check_expired_bans();
            if !unban_messages.is_empty() {
                self.broadcast_decisions(&unban_messages);
                proxy_wasm::hostcalls::log(
                    LogLevel::Info,
                    &format!("Removed {} expired bans", unban_messages.len()),
                )
                .ok();
            }
            return;
        }

        // LAPI call was successful - process response
        if let Some(body) = self.get_http_call_response_body(0, self.config.max_response_body_size) {
            if body.is_empty() {
                proxy_wasm::hostcalls::log(LogLevel::Debug, "Empty response from LAPI").ok();
                return;
            }

            proxy_wasm::hostcalls::log(
                LogLevel::Debug,
                &format!("LAPI response size: {} bytes", body.len()),
            )
            .ok();

            if let Ok(response_str) = String::from_utf8(body) {
                // Log first 200 chars for debugging
                let preview = if response_str.len() > 200 {
                    format!("{}...", &response_str[..200])
                } else {
                    response_str.clone()
                };
                proxy_wasm::hostcalls::log(
                    LogLevel::Debug,
                    &format!("LAPI response preview: {}", preview),
                )
                .ok();

                if let Ok(stream_response) = serde_json::from_str::<StreamResponse>(&response_str) {
                    let mut messages = Vec::new();

                    // Store lengths before iterating
                    let new_count = stream_response.new.len();
                    let deleted_count = stream_response.deleted.len();

                    // Process deleted decisions
                    for decision in stream_response.deleted {
                        proxy_wasm::hostcalls::log(
                            LogLevel::Debug,
                            &format!("Processing deleted decision: value='{}'", decision.value),
                        )
                        .ok();

                        if let Ok(ip_net) = parse_ip_with_cidr(&decision.value) {
                            proxy_wasm::hostcalls::log(
                                LogLevel::Debug,
                                &format!("Successfully parsed deleted IP: {:?}", ip_net),
                            )
                            .ok();

                            if let Some(ban_msg) = self.bans.remove(&ip_net) {
                                // Create unban message using the stored IpNet
                                let msg = BanMessage {
                                    ip: ban_msg.ip,
                                    remediation: "unban".to_string(),
                                    expiration: ban_msg.expiration,
                                };
                                messages.push(msg);
                                self.remove_from_expiration_queue(&ip_net);
                            }
                        } else {
                            proxy_wasm::hostcalls::log(
                                LogLevel::Warn,
                                &format!(
                                    "Failed to parse deleted IP: '{}' (length: {})",
                                    decision.value,
                                    decision.value.len()
                                ),
                            )
                            .ok();
                        }
                    }

                    // Process new decisions
                    for decision in stream_response.new {
                        let remediation = decision.remediation.unwrap_or_else(|| "ban".to_string());

                        proxy_wasm::hostcalls::log(
                            LogLevel::Debug,
                            &format!(
                                "Processing decision: value='{}', remediation='{}'",
                                decision.value, remediation
                            ),
                        )
                        .ok();

                        if let Ok(ip_net) = parse_ip_with_cidr(&decision.value) {
                            proxy_wasm::hostcalls::log(
                                LogLevel::Debug,
                                &format!("Successfully parsed IP: {:?}", ip_net),
                            )
                            .ok();

                            let ban_msg = BanMessage {
                                ip: ip_net,
                                remediation,
                                expiration: decision
                                    .expiration
                                    .as_deref()
                                    .unwrap_or("")
                                    .to_string(),
                            };

                            // Store the ban message
                            self.bans.insert(ip_net, ban_msg.clone());
                            messages.push(ban_msg);

                            // Add to expiration queue if it has an expiration
                            if let Some(exp_time) =
                                parse_expiration(decision.expiration.as_deref().unwrap_or(""))
                            {
                                self.add_to_expiration_queue(&ip_net, exp_time);
                            }
                        } else {
                            proxy_wasm::hostcalls::log(
                                LogLevel::Warn,
                                &format!(
                                    "Failed to parse IP for ban: '{}' (length: {})",
                                    decision.value,
                                    decision.value.len()
                                ),
                            )
                            .ok();
                        }
                    }

                    if !messages.is_empty() {
                        self.broadcast_decisions(&messages);
                        proxy_wasm::hostcalls::log(
                            LogLevel::Info,
                            &format!(
                                "Processed {} decisions ({} new, {} deleted)",
                                messages.len(),
                                new_count,
                                deleted_count
                            ),
                        )
                        .ok();
                    }
                } else {
                    proxy_wasm::hostcalls::log(
                        LogLevel::Error,
                        &format!("Failed to parse LAPI response: {}", response_str),
                    )
                    .ok();
                }
            } else {
                proxy_wasm::hostcalls::log(LogLevel::Error, "Failed to decode response body").ok();
            }
        } else {
            proxy_wasm::hostcalls::log(LogLevel::Error, "Failed to get response body").ok();
        }
    }
}

impl RootContext for CrowdsecUpdater {
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn on_vm_start(&mut self, _vm_configuration_size: usize) -> bool {
        self.log(LogLevel::Info, "CrowdSec updater VM started");
        self.worker_names_queue_id =
            proxy_wasm::hostcalls::register_shared_queue(STR_WORKER_NAMES_QUEUE).ok();
        true
    }

    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        self.log(LogLevel::Info, "CrowdSec updater configured");
        if let Some(config_bytes) = self.get_plugin_configuration() {
            match parse_config(&config_bytes) {
                Ok(config) => {
                    self.config = config;

                    // Set poll interval from config
                    self.set_tick_period(self.config.poll_interval);
                    info!(
                        "Updater started! Poll interval: {}s",
                        self.config.poll_interval.as_secs()
                    );
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

    fn on_queue_ready(&mut self, _queue_id: u32) {
        match proxy_wasm::hostcalls::dequeue_shared_queue(_queue_id) {
            Ok(Some(worker_uuid)) => match String::from_utf8(worker_uuid) {
                Ok(worker_uuid_str) => {
                    proxy_wasm::hostcalls::log(
                        LogLevel::Info,
                        &format!("Worker UUID: {}", worker_uuid_str),
                    )
                    .ok();
                    let worker_queue_name = format!("crowdsec_worker_{}", worker_uuid_str);

                    match proxy_wasm::hostcalls::resolve_shared_queue(
                        "crowdsec_filter",
                        &worker_queue_name,
                    ) {
                        Ok(Some(queue_id)) => {
                            self.worker_queues_ids.push(queue_id);
                        }
                        Ok(None) => {
                            proxy_wasm::hostcalls::log(
                                LogLevel::Error,
                                &format!("Worker queue not found: {}", worker_queue_name),
                            )
                            .ok();
                        }
                        Err(e) => {
                            proxy_wasm::hostcalls::log(
                                LogLevel::Error,
                                &format!(
                                    "Failed to resolve worker queue {}: {:?}",
                                    worker_queue_name, e
                                ),
                            )
                            .ok();
                        }
                    }
                }
                Err(e) => {
                    proxy_wasm::hostcalls::log(
                        LogLevel::Error,
                        &format!("Invalid UTF-8 in worker UUID: {:?}", e),
                    )
                    .ok();
                }
            },
            Ok(None) => {
                proxy_wasm::hostcalls::log(LogLevel::Error, "Empty read from worker names queue")
                    .ok();
            }
            Err(e) => {
                proxy_wasm::hostcalls::log(
                    LogLevel::Error,
                    &format!("Failed to dequeue worker names from shared queue: {:?}", e),
                )
                .ok();
            }
        }
    }

    fn on_tick(&mut self) {
        self.poll_lapi();
    }
}

impl Context for CrowdsecUpdater {
    fn on_http_call_response(
        &mut self,
        _token_id: u32,
        _num_headers: usize,
        _body_size: usize,
        _num_trailers: usize,
    ) {
        self.handle_lapi_response();
    }
}
