use flexbuffers;
use ipnet::Ipv4Net;
use iprange::IpRange;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use std::time::Duration;
use uuid;

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
    single_ips: HashSet<std::net::Ipv4Addr>, // Fast lookup for single IPs
    ip_range: IpRange<Ipv4Net>,              // For CIDR ranges
}

impl IpStorage {
    fn new() -> Self {
        Self {
            single_ips: HashSet::new(),
            ip_range: IpRange::new(),
        }
    }

    fn insert(&mut self, ip: String, is_range: bool) {
        let start_time = std::time::Instant::now();

        if is_range {
            // It's a CIDR range, parse as Ipv4Net
            if let Ok(network) = ip.parse::<Ipv4Net>() {
                let range_start = std::time::Instant::now();
                // More efficient: add to existing range instead of rebuilding
                let mut networks: Vec<Ipv4Net> = self.ip_range.iter().collect();
                networks.push(network);
                self.ip_range = networks.into_iter().collect();
                let range_duration = range_start.elapsed();
                let total_duration = start_time.elapsed();
                proxy_wasm::hostcalls::log(
                    LogLevel::Debug,
                    &format!(
                        "Inserted range {} in {:?} (total: {:?})",
                        ip, range_duration, total_duration
                    ),
                )
                .ok();
            }
        } else {
            // It's a single IP, store in HashSet for fast lookup
            if let Ok(ip_addr) = ip.parse::<std::net::Ipv4Addr>() {
                let single_start = std::time::Instant::now();
                self.single_ips.insert(ip_addr);
                let single_duration = single_start.elapsed();
                let total_duration = start_time.elapsed();
                proxy_wasm::hostcalls::log(
                    LogLevel::Debug,
                    &format!(
                        "Inserted single IP {} in {:?} (total: {:?})",
                        ip, single_duration, total_duration
                    ),
                )
                .ok();
            }
        }
    }

    fn contains(&self, ip: &str) -> bool {
        let start_time = std::time::Instant::now();

        // Check single IPs (fast HashSet lookup)
        if let Ok(ip_addr) = ip.parse::<std::net::Ipv4Addr>() {
            if self.single_ips.contains(&ip_addr) {
                let duration = start_time.elapsed();
                proxy_wasm::hostcalls::log(
                    LogLevel::Debug,
                    &format!("IP {} found in single_ips in {:?}", ip, duration),
                )
                .ok();
                return true;
            }

            // Check iprange radix tree for ranges
            let range_start = std::time::Instant::now();
            let result = self.ip_range.contains(&ip_addr);
            let range_duration = range_start.elapsed();
            let total_duration = start_time.elapsed();

            if result {
                proxy_wasm::hostcalls::log(
                    LogLevel::Debug,
                    &format!(
                        "IP {} found in ip_range in {:?} (total: {:?})",
                        ip, range_duration, total_duration
                    ),
                )
                .ok();
            } else {
                proxy_wasm::hostcalls::log(
                    LogLevel::Debug,
                    &format!(
                        "IP {} not found in any storage (total: {:?})",
                        ip, total_duration
                    ),
                )
                .ok();
            }
            return result;
        }

        let duration = start_time.elapsed();
        proxy_wasm::hostcalls::log(
            LogLevel::Debug,
            &format!("IP {} failed to parse as IPv4 (total: {:?})", ip, duration),
        )
        .ok();
        false
    }

    fn remove(&mut self, ip: &str) {
        if let Ok(ip_addr) = ip.parse::<std::net::Ipv4Addr>() {
            self.single_ips.remove(&ip_addr); // O(1) HashSet removal
        }
        // Also try to remove as a CIDR range
        if let Ok(network) = ip.parse::<Ipv4Net>() {
            self.ip_range.remove(network);
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct BanMessage {
    ip: String,
    remediation: String,
    expiration: String,
    is_range: bool, // true if it's a CIDR range, false if it's a single IP
}

struct CrowdsecFilter {
    has_sent_name: bool,
    bans: SharedBans,
    worker_uuid: uuid::Uuid,
}

impl Default for CrowdsecFilter {
    fn default() -> Self {
        Self {
            has_sent_name: false,
            bans: Rc::new(RefCell::new(IpStorage::new())),
            worker_uuid: uuid::Uuid::new_v4(),
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
        self.set_tick_period(Duration::from_millis(2000)); //To send the updater our uuid so we can receive decisions

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

    fn on_tick(&mut self) {
        //TODO: check if this we still have to have fake dependencies by waiting for for time before the updater is up
        let updater_queue_id;

        if self.has_sent_name {
            return;
        }
        //FIXME: put the queue name in a common lib between the updater and the worker
        let queue_name = "crowdsec_worker_names";
        match proxy_wasm::hostcalls::resolve_shared_queue(&"crowdsec_singleton", &queue_name) {
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
            bans: self.bans.clone(),
        }))
    }

    fn on_queue_ready(&mut self, queue_id: u32) {
        proxy_wasm::hostcalls::log(LogLevel::Info, &format!("Shared queue {queue_id} is ready"))
            .ok();
        match proxy_wasm::hostcalls::dequeue_shared_queue(queue_id) {
            Ok(Some(payload)) => {
                // Do not log the raw payload, just the number of decisions
                // Try to parse as a batch (flexbuffers vector)
                let batch_result = flexbuffers::from_slice::<Vec<BanMessage>>(&payload);
                if let Ok(batch) = batch_result {
                    proxy_wasm::hostcalls::log(
                        LogLevel::Info,
                        &format!("Dequeued batch with {} decisions", batch.len()),
                    )
                    .ok();
                    let mut bans = self.bans.borrow_mut();
                    for msg in batch {
                        if msg.remediation == "unban" {
                            bans.remove(&msg.ip);
                        } else {
                            bans.insert(msg.ip, msg.is_range);
                        }
                    }
                } else if let Ok(msg) = flexbuffers::from_slice::<BanMessage>(&payload) {
                    proxy_wasm::hostcalls::log(LogLevel::Info, "Dequeued single decision").ok();
                    // Fallback: try single message for backward compatibility
                    let mut bans = self.bans.borrow_mut();
                    if msg.remediation == "unban" {
                        bans.remove(&msg.ip);
                    } else {
                        bans.insert(msg.ip, msg.is_range);
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
}

impl Context for CrowdsecFilterHttp {}
impl HttpContext for CrowdsecFilterHttp {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // Get client IP from Envoy's source address property
        if let Some(addr_bytes) = self.get_property(vec!["source", "address"]) {
            if let Ok(addr) = String::from_utf8(addr_bytes) {
                // addr is typically in the form "IP:port"
                let ip = addr.split(':').next().unwrap_or("");
                if self.bans.borrow().contains(ip) {
                    proxy_wasm::hostcalls::log(LogLevel::Info, &format!("IP {} is banned!", ip))
                        .ok();
                    self.send_http_response(
                        403,
                        vec![("content-type", "text/plain")],
                        Some(b"Forbidden: Your IP is banned.\n"),
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
