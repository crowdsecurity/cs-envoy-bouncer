use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use serde::Serialize;
use std::collections::{HashSet};
use std::time::Duration;
use log::info;

#[derive(Deserialize, Debug, Clone)]
struct StreamResponse {
    new: Vec<Decision>,
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
                proxy_wasm::hostcalls::log(LogLevel::Error, &format!("JSON parse error: {:?}", e)).ok();
                return;
            }
        };

        // Handle deletions
        for dec in parsed.deleted.iter() {
            self.bans.remove(&dec.value);
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
	    if let Ok(json_string) = serde_json::to_string(&msg) {
		if let Some(queue_id) = self.queue_id {
		    info!("Enqueuing decisions {}", json_string);
		    let _ = proxy_wasm::hostcalls::enqueue_shared_queue(queue_id, Some(&json_string.as_bytes()));
		}
	    }
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

