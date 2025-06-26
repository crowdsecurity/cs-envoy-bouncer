use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use serde::Serialize;
use std::collections::{HashSet};
use std::time::Duration;
use std::rc::Rc;
use std::cell::RefCell;
use flexbuffers;

// We use Rc<RefCell<HashSet<String>>> for the ban list to share mutable state
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
type SharedBans = Rc<RefCell<HashSet<String>>>;

#[derive(Serialize, Deserialize, Debug)]
struct BanMessage {
    ip: String,
    remediation: String,
    expiration: String,
}

struct CrowdsecFilter {
    queue_id: Option<u32>,
    queue_read_count: u32,
    has_sent_name: bool,
    bans: SharedBans,
}

impl Default for CrowdsecFilter {
    fn default() -> Self {
        Self {
            queue_id: None,
            queue_read_count: 0,
            has_sent_name: false,
            bans: Rc::new(RefCell::new(HashSet::new())),
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
        self.set_tick_period(Duration::from_millis(2000));
        true
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
    
    fn on_tick(&mut self) {
        proxy_wasm::hostcalls::log(LogLevel::Info, &format!("queue read count: {}", self.queue_read_count)).ok();

        if self.has_sent_name {
            return;
        }
        let queue_name = "crowdsec_ban_update";
        self.queue_id = proxy_wasm::hostcalls::register_shared_queue(queue_name).ok();

        self.has_sent_name = true;
    }

    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(CrowdsecFilterHttp {
            context_id,
            bans: Rc::clone(&self.bans),
        }))
    }

    fn on_queue_ready(&mut self, queue_id: u32) {
        proxy_wasm::hostcalls::log(LogLevel::Info, &format!("Shared queue {queue_id} is ready")).ok();
        match proxy_wasm::hostcalls::dequeue_shared_queue(queue_id) {
            Ok(Some(payload)) => {
                // Do not log the raw payload, just the number of decisions
                // Try to parse as a batch (flexbuffers vector)
                let batch_result = flexbuffers::from_slice::<Vec<BanMessage>>(&payload);
                if let Ok(batch) = batch_result {
                    proxy_wasm::hostcalls::log(LogLevel::Info, &format!("Dequeued batch with {} decisions", batch.len())).ok();
                    let mut bans = self.bans.borrow_mut();
                    for msg in batch {
                        if msg.remediation == "unban" {
                            bans.remove(&msg.ip);
                        } else {
                            bans.insert(msg.ip);
                        }
                    }
                } else if let Ok(msg) = flexbuffers::from_slice::<BanMessage>(&payload) {
                    proxy_wasm::hostcalls::log(LogLevel::Info, "Dequeued single decision").ok();
                    // Fallback: try single message for backward compatibility
                    let mut bans = self.bans.borrow_mut();
                    if msg.remediation == "unban" {
                        bans.remove(&msg.ip);
                    } else {
                        bans.insert(msg.ip);
                    }
                }
                self.queue_read_count += 1;
            }
            Ok(None) => {
                proxy_wasm::hostcalls::log(LogLevel::Debug, "No data in shared queue").ok();
            }
            Err(e) => {
                proxy_wasm::hostcalls::log(LogLevel::Error, &format!("Failed to dequeue shared queue: {:?}", e)).ok();
            }
        }
    }
}

struct CrowdsecFilterHttp {
    context_id: u32,
    bans: SharedBans,
}

impl Context for CrowdsecFilterHttp {}
impl HttpContext for CrowdsecFilterHttp {
    fn on_http_request_headers(&mut self, num_headers: usize, end_of_stream: bool) -> Action {
        proxy_wasm::hostcalls::log(
            LogLevel::Info,
            &format!(
                "Received {num_headers} HTTP request headers | end_of_stream: {end_of_stream}"
            ),
        ).ok();

        // Extract IP from headers
        if let Some(ip) = self.get_http_request_header("x-forwarded-for") {
            if self.bans.borrow().contains(&ip) {
                self.send_http_response(
                    403,
                    vec![("content-type", "text/plain")],
                    Some(b"Forbidden: Your IP is banned.\n"),
                );
                return Action::Pause;
            }
        }
        Action::Continue
    }

    fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        proxy_wasm::hostcalls::log(
            LogLevel::Info,
            &format!(
                "Received HTTP request body of size {body_size} | end_of_stream: {end_of_stream}"
            ),
        ).ok();
        Action::Continue
    }

}
