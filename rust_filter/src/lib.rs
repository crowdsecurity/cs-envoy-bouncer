use flexbuffers;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use serde::Serialize;
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use std::time::Duration;

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
    has_sent_name: bool,
    bans: SharedBans,
    worker_uuid: uuid::Uuid,
    // bans: HashSet<String>
}

impl Default for CrowdsecFilter {
    fn default() -> Self {
        Self {
            has_sent_name: false,
            bans: Rc::new(RefCell::new(HashSet::new())),
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
            Ok(queue_id) => {
                proxy_wasm::hostcalls::log(
                    LogLevel::Debug,
                    &format!("Registered shared queue: {}", queue_id),
                )
                .ok();
                true
            }
            Err(e) => {
                proxy_wasm::hostcalls::log(
                    LogLevel::Error,
                    &format!("Failed to register shared queue: {:?}", e),
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
        match proxy_wasm::hostcalls::resolve_shared_queue(&"crowdsec", &queue_name) {
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
            Some(self.worker_uuid.as_bytes()),
        ) {
            Ok(()) => {
                proxy_wasm::hostcalls::log(LogLevel::Info, "Successfully enqueued worker UUID")
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

    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(CrowdsecFilterHttp {
            context_id,
            bans: Rc::clone(&self.bans),
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
        )
        .ok();

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
        )
        .ok();
        Action::Continue
    }
}
