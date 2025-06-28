use proxy_wasm::types::LogLevel;
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_tick_period")]
    pub tick_period: u64, // now in seconds

    #[serde(default = "default_worker_names_queue")]
    pub worker_names_queue: String,

    #[serde(default = "default_singleton_name")]
    pub singleton_name: String,

    #[serde(default = "default_response_code")]
    pub response_code: u16,

    #[serde(default = "default_response_message")]
    pub response_message: String,
}

/// Consolidated configuration for the CrowdSec filter
#[derive(Debug, Clone)]
pub struct FilterConfig {
    pub tick_period: Duration, // now in seconds
    pub worker_names_queue: String,
    pub singleton_name: String,
    pub response_code: u16,
    pub response_message: String,
}

impl From<Config> for FilterConfig {
    fn from(config: Config) -> Self {
        Self {
            tick_period: Duration::from_secs(config.tick_period),
            worker_names_queue: config.worker_names_queue,
            singleton_name: config.singleton_name,
            response_code: config.response_code,
            response_message: config.response_message,
        }
    }
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            tick_period: Duration::from_secs(2), // 2 seconds
            worker_names_queue: "crowdsec_worker_names".to_string(),
            singleton_name: "crowdsec_singleton".to_string(),
            response_code: 403,
            response_message: "Forbidden: Your IP is banned.".to_string(),
        }
    }
}

impl FilterConfig {
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.tick_period.as_secs() == 0 {
            return Err("tick_period must be greater than 0".to_string());
        }

        if self.worker_names_queue.is_empty() {
            return Err("worker_names_queue cannot be empty".to_string());
        }

        if self.singleton_name.is_empty() {
            return Err("singleton_name cannot be empty".to_string());
        }

        if self.response_code < 100 || self.response_code > 599 {
            return Err("response_code must be between 100 and 599".to_string());
        }

        Ok(())
    }
}

fn default_tick_period() -> u64 {
    2
} // 2 seconds
fn default_worker_names_queue() -> String {
    "crowdsec_worker_names".to_string()
}
fn default_singleton_name() -> String {
    "crowdsec_singleton".to_string()
}
fn default_response_code() -> u16 {
    403
}
fn default_response_message() -> String {
    "Forbidden: Your IP is banned.".to_string()
}

pub fn parse_config(config_bytes: &[u8]) -> Result<FilterConfig, Box<dyn std::error::Error>> {
    let config_str = String::from_utf8(config_bytes.to_vec())?;
    let config: Config = serde_yaml::from_str(&config_str)?;

    // Convert to FilterConfig
    let filter_config = FilterConfig::from(config);

    // Validate configuration
    if let Err(e) = filter_config.validate() {
        return Err(format!("Configuration validation failed: {}", e).into());
    }

    proxy_wasm::hostcalls::log(
        LogLevel::Info,
        &format!(
            "Filter tick period: {}s",
            filter_config.tick_period.as_secs()
        ),
    )
    .ok();
    proxy_wasm::hostcalls::log(
        LogLevel::Info,
        &format!("Response code: {}", filter_config.response_code),
    )
    .ok();

    Ok(filter_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_yaml;

    #[test]
    fn test_config_defaults() {
        let yaml = "";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.tick_period, 2);
        assert_eq!(config.worker_names_queue, "crowdsec_worker_names");
        assert_eq!(config.singleton_name, "crowdsec_singleton");
        assert_eq!(config.response_code, 403);
        assert_eq!(config.response_message, "Forbidden: Your IP is banned.");
    }

    #[test]
    fn test_config_custom_values() {
        let yaml = r#"
tick_period: 5
worker_names_queue: "custom_worker_names"
singleton_name: "custom_singleton"
response_code: 429
response_message: "Rate limited"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.tick_period, 5);
        assert_eq!(config.worker_names_queue, "custom_worker_names");
        assert_eq!(config.singleton_name, "custom_singleton");
        assert_eq!(config.response_code, 429);
        assert_eq!(config.response_message, "Rate limited");
    }

    #[test]
    fn test_parse_config_function() {
        let yaml = r#"
tick_period: 3
response_code: 451
"#;
        let result = parse_config(yaml.as_bytes());
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.tick_period.as_secs(), 3);
        assert_eq!(config.response_code, 451);
        // Defaults for others
        assert_eq!(config.worker_names_queue, "crowdsec_worker_names");
        assert_eq!(config.singleton_name, "crowdsec_singleton");
    }

    #[test]
    fn test_filter_config_validation() {
        let mut config = FilterConfig::default();

        // Valid config should pass
        assert!(config.validate().is_ok());

        // Invalid tick_period
        config.tick_period = Duration::from_secs(0);
        assert!(config.validate().is_err());

        // Reset and test invalid response_code
        config = FilterConfig::default();
        config.response_code = 999;
        assert!(config.validate().is_err());

        // Reset and test empty worker_names_queue
        config = FilterConfig::default();
        config.worker_names_queue = String::new();
        assert!(config.validate().is_err());

        // Reset and test empty singleton_name
        config = FilterConfig::default();
        config.singleton_name = String::new();
        assert!(config.validate().is_err());
    }
}
