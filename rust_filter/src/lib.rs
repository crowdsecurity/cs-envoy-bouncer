use proxy_wasm::traits::*;
use proxy_wasm::types::*;
//use serde::Deserialize;
//use serde::Serialize;
use std::collections::{HashSet};
use std::time::Duration;
//use std::cell::RefCell;
//use std::rc::Rc;

struct CrowdsecFilter {
    queue_id: Option<u32>,
    queue_read_count: u32,
    has_sent_name: bool,
    // bans: HashSet<String>
}

impl Default for CrowdsecFilter {
    fn default() -> Self {
        Self {
            queue_id: None,
            queue_read_count: 0,
            has_sent_name: false,
            // bans: HashSet::new()
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
        Some(Box::new(CrowdsecFilterHttp { context_id }))
    }

    fn on_queue_ready(&mut self, queue_id: u32) {
        proxy_wasm::hostcalls::log(LogLevel::Info, &format!("Shared queue {queue_id} is ready")).ok();
        match proxy_wasm::hostcalls::dequeue_shared_queue(queue_id) {
            Ok(Some(payload)) => {
                proxy_wasm::hostcalls::log(LogLevel::Info, &format!("Dequeued from queue: {:?}", String::from_utf8_lossy(&payload))).ok();
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
