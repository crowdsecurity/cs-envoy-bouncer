use flexbuffers;
use log::info;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use std::time::Duration;

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

//FIXME: move this to a common crate
#[derive(Serialize)]
struct BanMessage<'a> {
    ip: &'a str,
    remediation: &'a str,
    expiration: &'a str,
}

//TODO: should this be moved to another crate ?
#[derive(Deserialize, Debug, Clone)]
struct Decision {
    value: String,
    remediation: Option<String>,
    expiration: Option<String>,
}

struct CrowdsecUpdater {
    bans: HashSet<String>,
    is_startup: bool,
    worker_names_queue_id: Option<u32>,
    worker_queues_ids: Vec<u32>,
}

impl Default for CrowdsecUpdater {
    fn default() -> Self {
        Self {
            bans: HashSet::new(),
            worker_names_queue_id: None,
            is_startup: true,
            worker_queues_ids: vec![],
        }
    }
}

const STR_WORKER_NAMES_QUEUE: &str = "crowdsec_worker_names";

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(CrowdsecUpdater::default()) });
}}

impl RootContext for CrowdsecUpdater {
    fn on_vm_start(&mut self, _: usize) -> bool {
        self.worker_names_queue_id =
            proxy_wasm::hostcalls::register_shared_queue(&STR_WORKER_NAMES_QUEUE).ok();
        self.set_tick_period(Duration::from_secs(10));
        info!("Updater started!");
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
                    return;
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
        if self.worker_queues_ids.len() == 0 {
            proxy_wasm::hostcalls::log(LogLevel::Error, "Worker queues not initialized").ok();
            return;
        }

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
        )
        .ok();
    }
}

impl Context for CrowdsecUpdater {
    fn on_http_call_response(
        &mut self,
        _token_id: u32,
        _num_headers: usize,
        body_size: usize,
        _num_trailers: usize,
    ) {
        info!("Parsing the decisions");
        let body = self
            .get_http_call_response_body(0, body_size)
            .unwrap_or_default();

        let parsed: serde_json::Result<StreamResponse> = serde_json::from_slice(&body);
        let parsed = match parsed {
            Ok(p) => p,
            Err(e) => {
                // Print the full JSON body for debugging
                proxy_wasm::hostcalls::log(LogLevel::Error, &format!("JSON parse error: {:?}", e))
                    .ok();
                proxy_wasm::hostcalls::log(
                    LogLevel::Error,
                    &format!("Full JSON body: {}", String::from_utf8_lossy(&body)),
                )
                .ok();
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

        self.send_batched(&to_send);

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
    fn send_batched(&self, messages: &[BanMessage]) {
        for chunk in messages.chunks(BATCH_SIZE) {
            self.broadcast_decisions(chunk);
        }
    }

    fn broadcast_decisions(&self, decisions: &[BanMessage]) {
        let mut s = flexbuffers::FlexbufferSerializer::new();
        if let Err(e) = decisions.serialize(&mut s) {
            proxy_wasm::hostcalls::log(
                LogLevel::Error,
                &format!("Flexbuffers serialization error: {:?}", e),
            )
            .ok();
        }
        let data = s.view();
        if data.len() > MAX_BATCH_BYTES {
            proxy_wasm::hostcalls::log(
                LogLevel::Warn,
                &format!(
                    "Batch: {} messages, {} bytes (exceeds 12KB!)",
                    decisions.len(),
                    data.len()
                ),
            )
            .ok();
        } else {
            proxy_wasm::hostcalls::log(
                LogLevel::Info,
                &format!("Batch: {} messages, {} bytes", decisions.len(), data.len()),
            )
            .ok();
        }

        for queue_id in &self.worker_queues_ids {
            match proxy_wasm::hostcalls::enqueue_shared_queue(*queue_id, Some(data)) {
                Ok(_) => {}
                Err(e) => {
                    proxy_wasm::hostcalls::log(
                        LogLevel::Error,
                        &format!("Failed to enqueue decision: {:?}", e),
                    )
                    .ok();
                    continue;
                }
            }
        }
    }
}
