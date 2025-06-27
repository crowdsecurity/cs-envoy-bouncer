use flexbuffers;
use log::info;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use serde::Serialize;
use serde_yaml::Value;
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
#[derive(Serialize, Clone)]
struct BanMessage<'a> {
    ip: &'a str,
    remediation: &'a str,
    expiration: &'a str,
    is_range: bool, // true if it's a CIDR range, false if it's a single IP
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
    api_key: String,
    cluster_name: String,
    crowdsec_url: String,
    scopes: Vec<String>,
    origins: Vec<String>,
    scenarios_containing: Vec<String>,
    scenarios_not_containing: Vec<String>,
}

impl Default for CrowdsecUpdater {
    fn default() -> Self {
        Self {
            bans: HashSet::new(),
            worker_names_queue_id: None,
            is_startup: true,
            worker_queues_ids: vec![],
            api_key: String::new(),
            cluster_name: String::new(),
            crowdsec_url: String::new(),
            scopes: Vec::new(),
            origins: Vec::new(),
            scenarios_containing: Vec::new(),
            scenarios_not_containing: Vec::new(),
        }
    }
}

const STR_WORKER_NAMES_QUEUE: &str = "crowdsec_worker_names";

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(CrowdsecUpdater::default()) });
}}

impl CrowdsecUpdater {
    fn send_batched(&self, messages: &[BanMessage]) {
        if messages.is_empty() {
            return;
        }

        let mut batch = Vec::new();
        let mut current_batch_size = 0;

        for msg in messages {
            let msg_bytes = flexbuffers::to_vec(msg).unwrap();
            if current_batch_size + msg_bytes.len() > MAX_BATCH_BYTES || batch.len() >= BATCH_SIZE {
                // Send current batch
                self.broadcast_decisions(&batch);
                batch.clear();
                current_batch_size = 0;
            }
            batch.push(msg.clone());
            current_batch_size += msg_bytes.len();
        }

        // Send remaining batch
        if !batch.is_empty() {
            self.broadcast_decisions(&batch);
        }
    }

    fn is_cidr_range(&self, value: &str) -> bool {
        // Check if it contains a slash (CIDR notation)
        value.contains('/')
    }
}

impl RootContext for CrowdsecUpdater {
    fn on_vm_start(&mut self, _: usize) -> bool {
        self.worker_names_queue_id =
            proxy_wasm::hostcalls::register_shared_queue(&STR_WORKER_NAMES_QUEUE).ok();
        true
    }

    fn on_configure(&mut self, _: usize) -> bool {
        // Set defaults
        self.cluster_name = "crowdsec_cluster".to_string();
        self.crowdsec_url = "http://crowdsec:8080".to_string();

        if let Some(config_bytes) = self.get_plugin_configuration() {
            if let Ok(config_str) = String::from_utf8(config_bytes) {
                if let Ok(yaml) = serde_yaml::from_str::<Value>(&config_str) {
                    if let Some(secs) = yaml.get("poll_interval").and_then(|v| v.as_u64()) {
                        self.set_tick_period(Duration::from_secs(secs));
                        info!("Updater started! Poll interval: {}s", secs);
                    }
                    if let Some(key) = yaml.get("api_key").and_then(|v| v.as_str()) {
                        self.api_key = key.to_string();
                    } else {
                        proxy_wasm::hostcalls::log(LogLevel::Warn, "No API key configured!").ok();
                    }
                    if let Some(cluster) = yaml.get("cluster_name").and_then(|v| v.as_str()) {
                        self.cluster_name = cluster.to_string();
                    }
                    if let Some(url) = yaml.get("crowdsec_url").and_then(|v| v.as_str()) {
                        self.crowdsec_url = url.to_string();
                    }
                    if let Some(scopes) = yaml.get("scopes").and_then(|v| v.as_sequence()) {
                        self.scopes = scopes
                            .iter()
                            .filter_map(|v| v.as_str())
                            .map(|s| s.to_string())
                            .collect();
                    }
                    if let Some(origins) = yaml.get("origins").and_then(|v| v.as_sequence()) {
                        self.origins = origins
                            .iter()
                            .filter_map(|v| v.as_str())
                            .map(|s| s.to_string())
                            .collect();
                    }
                    if let Some(scenarios) = yaml
                        .get("scenarios_containing")
                        .and_then(|v| v.as_sequence())
                    {
                        self.scenarios_containing = scenarios
                            .iter()
                            .filter_map(|v| v.as_str())
                            .map(|s| s.to_string())
                            .collect();
                    }
                    if let Some(scenarios) = yaml
                        .get("scenarios_not_containing")
                        .and_then(|v| v.as_sequence())
                    {
                        self.scenarios_not_containing = scenarios
                            .iter()
                            .filter_map(|v| v.as_str())
                            .map(|s| s.to_string())
                            .collect();
                    }
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

        let mut path = if self.is_startup {
            "/v1/decisions/stream?startup=true".to_string()
        } else {
            "/v1/decisions/stream".to_string()
        };

        // Build query parameters
        let mut query_params = Vec::new();

        if !self.scopes.is_empty() {
            query_params.push(format!("scopes={}", self.scopes.join(",")));
        }
        if !self.origins.is_empty() {
            query_params.push(format!("origins={}", self.origins.join(",")));
        }
        if !self.scenarios_containing.is_empty() {
            query_params.push(format!(
                "scenarios_containing={}",
                self.scenarios_containing.join(",")
            ));
        }
        if !self.scenarios_not_containing.is_empty() {
            query_params.push(format!(
                "scenarios_not_containing={}",
                self.scenarios_not_containing.join(",")
            ));
        }

        if !query_params.is_empty() {
            let separator = if path.contains('?') { "&" } else { "?" };
            path = format!("{}{}{}", path, separator, query_params.join("&"));
        }

        self.is_startup = false;

        let headers = vec![
            (":method", "GET"),
            (":path", &path),
            (":authority", "crowdsec"),
            ("x-api-key", &self.api_key),
        ];
        info!("Asking the crowdsec LAPI for decisions {path}");
        if let Err(e) = self.dispatch_http_call(
            &self.cluster_name,
            headers,
            None,
            vec![],
            Duration::from_secs(5),
        ) {
            proxy_wasm::hostcalls::log(
                LogLevel::Error,
                &format!("Failed to dispatch HTTP call: {:?}", e),
            )
            .ok();
        }
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
                is_range: self.is_cidr_range(&dec.value),
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
                is_range: self.is_cidr_range(&dec.value),
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
