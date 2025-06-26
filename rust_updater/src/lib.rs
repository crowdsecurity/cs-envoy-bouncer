use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use serde::Serialize;
use std::collections::{HashSet};
use std::time::Duration;
use log::info;
use flexbuffers;

const MAX_BATCH_BYTES: usize = 12 * 1024; // 12KB, safe for ABI, make configurable if needed
const BATCH_SIZE: usize = 1000; // We should make it configurable 


// this is a workaround for the fact that the json is sometimes null
// and we need to make sure that the vec is empty if the json is null
// example: {"deleted":null,"new":null}
// instead of {"deleted":[],"new":[]}
fn null_to_empty_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Ok(Option::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Deserialize, Debug, Clone)]
struct StreamResponse {
    #[serde(default, deserialize_with = "null_to_empty_vec")]
    new: Vec<Decision>,
    #[serde(default, deserialize_with = "null_to_empty_vec")]
    deleted: Vec<Decision>,
}

#[derive(Serialize)]
struct BanMessage<'a> {
    ip: &'a str,
    remediation: &'a str,
    expiration: &'a str,
}

#[derive(Deserialize, Debug, Clone)]
struct Decision {
    value: String,
    remediation: Option<String>,
    expiration: Option<String>,
}

struct CrowdsecUpdater {
    bans: HashSet<String>,
    queue_id: Option<u32>,
    is_startup: bool,
}

impl Default for CrowdsecUpdater {
    fn default() -> Self {
        Self { bans: HashSet::new(), queue_id: None, is_startup: true }
    }
}

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(CrowdsecUpdater::default()) });
}}

impl RootContext for CrowdsecUpdater {
    fn on_vm_start(&mut self, _: usize) -> bool {
        let _queue_name = "crowdsec_ban_update";
//        self.queue_id = proxy_wasm::hostcalls::register_shared_queue(queue_name).ok();
        self.set_tick_period(Duration::from_secs(10));
        info!("Updater started!");
        true
    }
    fn on_tick(&mut self) {
	self.queue_id = proxy_wasm::hostcalls::resolve_shared_queue("crowdsec_filter", "crowdsec_ban_update").ok().flatten();

    let path = if self.is_startup {
        "/v1/decisions/stream?startup=true"
    } else {
        "/v1/decisions/stream"
    };
    self.is_startup = false;

        let headers = vec![
            (":method", "GET"),
            (":path", path),
            (":authority", "crowdsec"),
            ("x-api-key", "thisisabouncerkey"),
        ];
        info!("Askin the crowdsec LAPI for decisions {path}");
        self.dispatch_http_call(
            "crowdsec_cluster",
            headers,
            None,
            vec![],
            Duration::from_secs(5),
        ).ok();
    }
}

impl Context for CrowdsecUpdater {
    fn on_http_call_response(&mut self, _token_id: u32, _num_headers: usize, body_size: usize, _num_trailers: usize) {
        info!("Parsing the decisions");
        let body = self.get_http_call_response_body(0, body_size).unwrap_or_default();

        let parsed: serde_json::Result<StreamResponse> = serde_json::from_slice(&body);
        let parsed = match parsed {
            Ok(p) => p,
            Err(e) => {
                // Print the full JSON body for debugging
                proxy_wasm::hostcalls::log(LogLevel::Error, &format!("JSON parse error: {:?}", e)).ok();
                proxy_wasm::hostcalls::log(LogLevel::Error, &format!("Full JSON body: {}", String::from_utf8_lossy(&body))).ok();
                return;
            }
        };

        let mut to_send = Vec::new();

        // Handle deletions
        for dec in parsed.deleted.iter() {
            self.bans.remove(&dec.value);
            let msg = BanMessage {
                ip: &dec.value,
                remediation: "unban",
                expiration: "",
            };
            to_send.push(msg);
        }

        // Handle new bans
        for dec in parsed.new.iter() {
            let remediation = dec.remediation.as_deref().unwrap_or("ban");
            let expiration = dec.expiration.as_deref().unwrap_or("");
            let msg = BanMessage {
                ip: &dec.value,
                remediation,
                expiration,
            };
            to_send.push(msg);
        }

        if let Some(queue_id) = self.queue_id {
            self.send_batched(queue_id, &to_send);
        }

        proxy_wasm::hostcalls::log(
            LogLevel::Info,
            &format!(
                "Processed stream: {} deleted, {} new, {} total active bans",
                parsed.deleted.len(),
                parsed.new.len(),
                self.bans.len()
            ),
        )
        .ok();
    }
}

impl CrowdsecUpdater {
    fn send_batched(&self, queue_id: u32, messages: &[BanMessage]) {
        let mut batch_count = 0;
        for chunk in messages.chunks(BATCH_SIZE) {
            let mut s = flexbuffers::FlexbufferSerializer::new();
            if let Err(e) = chunk.serialize(&mut s) {
                proxy_wasm::hostcalls::log(LogLevel::Error, &format!("Flexbuffers serialization error: {:?}", e)).ok();
                continue;
            }
            let data = s.view();
            if data.len() > MAX_BATCH_BYTES {
                proxy_wasm::hostcalls::log(LogLevel::Warn, &format!("Batch {}: {} messages, {} bytes (exceeds 16KB!)", batch_count + 1, chunk.len(), data.len())).ok();
            } else {
                proxy_wasm::hostcalls::log(LogLevel::Info, &format!("Batch {}: {} messages, {} bytes", batch_count + 1, chunk.len(), data.len())).ok();
            }
            let _ = proxy_wasm::hostcalls::enqueue_shared_queue(queue_id, Some(data));
            batch_count += 1;
        }
    }
}

