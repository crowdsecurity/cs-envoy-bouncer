use log::info;
use proxy_wasm::types::LogLevel;
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_poll_interval")]
    pub poll_interval: u64,

    #[serde(default)]
    pub api_key: String,

    #[serde(default = "default_cluster_name")]
    pub cluster_name: String,

    #[serde(default = "default_crowdsec_url")]
    pub crowdsec_url: String,

    #[serde(default)]
    pub scopes: Vec<String>,

    #[serde(default)]
    pub origins: Vec<String>,

    #[serde(default)]
    pub scenarios_containing: Vec<String>,

    #[serde(default)]
    pub scenarios_not_containing: Vec<String>,

    #[serde(default = "default_lapi_timeout")]
    pub lapi_timeout: u64,

    #[serde(default = "default_max_response_body_size")]
    pub max_response_body_size: usize,

    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    #[serde(default = "default_max_batch_bytes")]
    pub max_batch_bytes: usize,
}

/// Consolidated configuration for the CrowdSec updater
#[derive(Debug, Clone)]
pub struct UpdaterConfig {
    pub poll_interval: Duration,
    pub api_key: String,
    pub cluster_name: String,
    pub crowdsec_url: String,
    pub scopes: Vec<String>,
    pub origins: Vec<String>,
    pub scenarios_containing: Vec<String>,
    pub scenarios_not_containing: Vec<String>,
    pub lapi_timeout: Duration,
    pub max_response_body_size: usize,
    pub batch_size: usize,
    pub max_batch_bytes: usize,
}

impl From<Config> for UpdaterConfig {
    fn from(config: Config) -> Self {
        Self {
            poll_interval: Duration::from_secs(config.poll_interval),
            api_key: config.api_key,
            cluster_name: config.cluster_name,
            crowdsec_url: config.crowdsec_url,
            scopes: config.scopes,
            origins: config.origins,
            scenarios_containing: config.scenarios_containing,
            scenarios_not_containing: config.scenarios_not_containing,
            lapi_timeout: Duration::from_secs(config.lapi_timeout),
            max_response_body_size: config.max_response_body_size,
            batch_size: config.batch_size,
            max_batch_bytes: config.max_batch_bytes,
        }
    }
}

impl UpdaterConfig {
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.poll_interval.as_secs() == 0 {
            return Err("poll_interval must be greater than 0".to_string());
        }

        if self.lapi_timeout.as_secs() == 0 {
            return Err("lapi_timeout must be greater than 0".to_string());
        }

        if self.cluster_name.is_empty() {
            return Err("cluster_name cannot be empty".to_string());
        }

        if self.crowdsec_url.is_empty() {
            return Err("crowdsec_url cannot be empty".to_string());
        }

        Ok(())
    }
}

impl Default for UpdaterConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(30),
            api_key: String::new(),
            cluster_name: "crowdsec_cluster".to_string(),
            crowdsec_url: "http://crowdsec:8080".to_string(),
            scopes: Vec::new(),
            origins: Vec::new(),
            scenarios_containing: Vec::new(),
            scenarios_not_containing: Vec::new(),
            lapi_timeout: Duration::from_secs(10),
            max_response_body_size: 10 * 1024 * 1024, // 10MB default
            batch_size: 1000,
            max_batch_bytes: 12 * 1024, // 12KB
        }
    }
}

fn default_poll_interval() -> u64 {
    30
}
fn default_cluster_name() -> String {
    "crowdsec_cluster".to_string()
}
fn default_crowdsec_url() -> String {
    "http://crowdsec:8080".to_string()
}
fn default_lapi_timeout() -> u64 {
    10
}
fn default_max_response_body_size() -> usize {
    10 * 1024 * 1024 // 10MB
}
fn default_batch_size() -> usize {
    1000
}
fn default_max_batch_bytes() -> usize {
    12 * 1024 // 12KB
}

pub fn parse_config(config_bytes: &[u8]) -> Result<UpdaterConfig, Box<dyn std::error::Error>> {
    let config_str = String::from_utf8(config_bytes.to_vec())?;
    let config: Config = serde_yaml::from_str(&config_str)?;

    // Convert to UpdaterConfig
    let updater_config = UpdaterConfig::from(config);

    // Validate configuration
    if let Err(e) = updater_config.validate() {
        return Err(format!("Configuration validation failed: {}", e).into());
    }

    // Log warning if no API key is configured
    if updater_config.api_key.is_empty() {
        proxy_wasm::hostcalls::log(LogLevel::Warn, "No API key configured!").ok();
    }

    info!("LAPI timeout: {}s", updater_config.lapi_timeout.as_secs());

    Ok(updater_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_yaml;

    #[test]
    fn test_config_defaults() {
        let yaml = "";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.poll_interval, 30);
        assert_eq!(config.api_key, "");
        assert_eq!(config.cluster_name, "crowdsec_cluster");
        assert_eq!(config.crowdsec_url, "http://crowdsec:8080");
        assert_eq!(config.lapi_timeout, 10);
        assert!(config.scopes.is_empty());
        assert!(config.origins.is_empty());
        assert!(config.scenarios_containing.is_empty());
        assert!(config.scenarios_not_containing.is_empty());
    }

    #[test]
    fn test_config_custom_values() {
        let yaml = r#"
poll_interval: 60
api_key: "mykey"
cluster_name: "custom_cluster"
crowdsec_url: "http://custom:8080"
scopes: ["foo", "bar"]
origins: ["baz"]
scenarios_containing: ["ssh"]
scenarios_not_containing: ["http"]
lapi_timeout: 42
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.poll_interval, 60);
        assert_eq!(config.api_key, "mykey");
        assert_eq!(config.cluster_name, "custom_cluster");
        assert_eq!(config.crowdsec_url, "http://custom:8080");
        assert_eq!(config.lapi_timeout, 42);
        assert_eq!(config.scopes, vec!["foo", "bar"]);
        assert_eq!(config.origins, vec!["baz"]);
        assert_eq!(config.scenarios_containing, vec!["ssh"]);
        assert_eq!(config.scenarios_not_containing, vec!["http"]);
    }

    #[test]
    fn test_parse_config_function() {
        let yaml = r#"
api_key: "abc"
"#;
        let result = parse_config(yaml.as_bytes());
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.api_key, "abc");
        // Defaults for others
        assert_eq!(config.poll_interval.as_secs(), 30);
        assert_eq!(config.cluster_name, "crowdsec_cluster");
    }

    #[test]
    fn test_config_partial_values() {
        let yaml = r#"
poll_interval: 45
api_key: "partial_key"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.poll_interval, 45);
        assert_eq!(config.api_key, "partial_key");
        // Other fields should have defaults
        assert_eq!(config.cluster_name, "crowdsec_cluster");
        assert_eq!(config.crowdsec_url, "http://crowdsec:8080");
        assert_eq!(config.lapi_timeout, 10);
        assert!(config.scopes.is_empty());
    }

    #[test]
    fn test_config_empty_arrays() {
        let yaml = r#"
scopes: []
origins: []
scenarios_containing: []
scenarios_not_containing: []
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.scopes.is_empty());
        assert!(config.origins.is_empty());
        assert!(config.scenarios_containing.is_empty());
        assert!(config.scenarios_not_containing.is_empty());
    }

    #[test]
    fn test_updater_config_validation() {
        let mut config = UpdaterConfig::default();

        // Valid config should pass
        assert!(config.validate().is_ok());

        // Invalid poll_interval
        config.poll_interval = Duration::from_secs(0);
        assert!(config.validate().is_err());

        // Reset and test invalid lapi_timeout
        config = UpdaterConfig::default();
        config.lapi_timeout = Duration::from_secs(0);
        assert!(config.validate().is_err());

        // Reset and test empty cluster_name
        config = UpdaterConfig::default();
        config.cluster_name = String::new();
        assert!(config.validate().is_err());

        // Reset and test empty crowdsec_url
        config = UpdaterConfig::default();
        config.crowdsec_url = String::new();
        assert!(config.validate().is_err());
    }
}
