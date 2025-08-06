use flexbuffers;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};


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
pub struct StreamResponse {
    #[serde(default, deserialize_with = "null_to_empty_vec")]
    pub new: Vec<Decision>,
    #[serde(default, deserialize_with = "null_to_empty_vec")]
    pub deleted: Vec<Decision>,
}

#[derive(Serialize, Clone)]
pub struct BanMessage {
    pub ip: IpNet,
    pub remediation: String,
    pub expiration: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Decision {
    pub value: String,
    pub remediation: Option<String>,
    pub expiration: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ExpirationEntry {
    pub expiration: SystemTime,
    pub ip: IpNet,
}

impl PartialEq for ExpirationEntry {
    fn eq(&self, other: &Self) -> bool {
        self.expiration == other.expiration
    }
}

impl Eq for ExpirationEntry {}

impl PartialOrd for ExpirationEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExpirationEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse order so earliest expiration comes first
        self.expiration.cmp(&other.expiration)
    }
}

// Utility functions
pub fn send_batched(
    messages: &[BanMessage],
    batch_size: usize,
    max_batch_bytes: usize,
) -> Result<Vec<Vec<BanMessage>>, Box<dyn std::error::Error>> {
    if messages.is_empty() {
        return Ok(Vec::new());
    }

    let mut batches = Vec::new();
    let mut current_batch = Vec::new();
    let mut current_batch_size = 0;

    for msg in messages {
        let msg_bytes =
            flexbuffers::to_vec(msg).map_err(|e| format!("Failed to serialize message: {}", e))?;

        if current_batch_size + msg_bytes.len() > max_batch_bytes
            || current_batch.len() >= batch_size
        {
            // Send current batch
            if !current_batch.is_empty() {
                batches.push(current_batch);
                current_batch = Vec::new();
                current_batch_size = 0;
            }
        }
        current_batch.push(msg.clone());
        current_batch_size += msg_bytes.len();
    }

    // Add remaining batch
    if !current_batch.is_empty() {
        batches.push(current_batch);
    }

    Ok(batches)
}

pub fn parse_expiration(expiration_str: &str) -> Option<SystemTime> {
    if expiration_str.is_empty() {
        return None; // No expiration
    }

    // Parse RFC3339 format (e.g., "2023-12-31T23:59:59Z")
    if let Ok(datetime) = chrono::DateTime::parse_from_rfc3339(expiration_str) {
        let timestamp = datetime.timestamp();
        return Some(UNIX_EPOCH + Duration::from_secs(timestamp as u64));
    }

    // Try parsing as Unix timestamp
    if let Ok(timestamp) = expiration_str.parse::<i64>() {
        return Some(UNIX_EPOCH + Duration::from_secs(timestamp as u64));
    }

    None
}

pub fn build_query_params(
    is_startup: bool,
    scopes: &[String],
    origins: &[String],
    scenarios_containing: &[String],
    scenarios_not_containing: &[String],
) -> String {
    let mut query_params = Vec::new();

    if is_startup {
        query_params.push("startup=true".to_string());
    }

    for scope in scopes {
        query_params.push(format!("scopes={}", scope));
    }

    for origin in origins {
        query_params.push(format!("origins={}", origin));
    }

    for scenario in scenarios_containing {
        query_params.push(format!("scenarios_containing={}", scenario));
    }

    for scenario in scenarios_not_containing {
        query_params.push(format!("scenarios_not_containing={}", scenario));
    }

    if query_params.is_empty() {
        String::new()
    } else {
        format!("?{}", query_params.join("&"))
    }
}

// Helper function to parse IP addresses with automatic /32 suffix
pub fn parse_ip_with_cidr(ip_str: &str) -> Result<IpNet, Box<dyn std::error::Error>> {
    // If it already contains a slash, it's already in CIDR format
    if ip_str.contains('/') {
        return Ok(ip_str.parse::<IpNet>()?);
    }

    // If it's a single IP, add /32 suffix
    let cidr_str = format!("{}/32", ip_str);
    Ok(cidr_str.parse::<IpNet>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use std::collections::HashMap;

    #[test]
    fn test_stream_response_ban_unban() {
        // Fake JSON simulating a CrowdSec LAPI response with new and deleted decisions
        let json = r#"
        {
            "new": [
                {"value": "1.2.3.4", "remediation": "ban", "expiration": null},
                {"value": "5.6.7.8/24", "remediation": "ban", "expiration": null}
            ],
            "deleted": [
                {"value": "9.9.9.9", "remediation": "ban", "expiration": null}
            ]
        }
        "#;

        // Parse the JSON into a StreamResponse struct
        let stream: StreamResponse = serde_json::from_str(json).unwrap();

        // Simulate the updater's ban storage (HashMap)
        let mut bans = HashMap::<IpNet, BanMessage>::new();

        // Add new bans from the "new" field
        for decision in &stream.new {
            // Parse the IP/CIDR range
            let ip_net = match parse_ip_with_cidr(&decision.value) {
                Ok(ip_net) => ip_net,
                Err(e) => {
                    log::warn!("Failed to parse IP/CIDR '{}': {}", decision.value, e);
                    continue;
                }
            };
            let ban_msg = BanMessage {
                ip: ip_net.clone(),
                remediation: decision
                    .remediation
                    .clone()
                    .unwrap_or_else(|| "ban".to_string()),
                expiration: "".to_string(),
            };
            bans.insert(ip_net, ban_msg);
        }

        // Remove bans from the "deleted" field
        for decision in &stream.deleted {
            // Parse the IP/CIDR range
            let ip_net = match parse_ip_with_cidr(&decision.value) {
                Ok(ip_net) => ip_net,
                Err(e) => {
                    log::warn!("Failed to parse IP/CIDR '{}': {}", decision.value, e);
                    continue;
                }
            };
            bans.remove(&ip_net);
        }

        // Verify the final state
        assert_eq!(bans.len(), 1);
        assert!(bans.contains_key(&"1.2.3.4".parse::<IpNet>().unwrap()));
    }

    #[test]
    fn test_utility_functions() {
        // Test parse_expiration
        assert!(parse_expiration("").is_none());
        assert!(parse_expiration("invalid").is_none());

        // Test valid Unix timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(parse_expiration(&timestamp.to_string()).is_some());

        // Test valid RFC3339
        assert!(parse_expiration("2023-12-31T23:59:59Z").is_some());
    }

    #[test]
    fn test_send_batched() {
        // Test empty messages
        let batches = send_batched(&[]);
        assert!(batches.is_ok());
        assert!(batches.unwrap().is_empty());

        // Test single message
        let messages = vec![BanMessage {
            ip: "1.2.3.4".parse().unwrap(),
            remediation: "ban".to_string(),
            expiration: "".to_string(),
        }];
        let batches = send_batched(&messages);
        assert!(batches.is_ok());
        let batches = batches.unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 1);
    }
}
