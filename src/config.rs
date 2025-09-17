// src/config.rs

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Serialize)]
pub struct AppConfig {
    pub db_path: String,
    pub master_key_hex: String,

    #[serde(default)]
    pub web_server: ServerConfig,

    #[serde(default)]
    pub grpc_server: ServerConfig,

    #[serde(default)]
    pub ldap_server: LdapServerConfig,

    #[serde(default)]
    pub security: SecurityConfig,

    #[serde(default)]
    pub logging: LoggingConfig,

    #[serde(default)]
    pub paths: PathsConfig,

    #[serde(default)]
    pub metrics: MetricsConfig,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct ServerConfig {
    pub address: Option<String>,
    #[serde(default)]
    pub enable_tls: bool,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default = "default_max_request_size")]
    pub max_request_size: u64,
}

fn default_max_request_size() -> u64 {
    10 * 1024 * 1024 // 10 MB
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct LdapServerConfig {
    pub address: Option<String>,
    #[serde(default)]
    pub enable_tls: bool,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub allow_anonymous_bind: bool,
    #[serde(default = "default_base_dn")]
    pub base_dn: String,
}

fn default_base_dn() -> String {
    "DC=corp,DC=acme,DC=com".to_string()
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct SecurityConfig {
    #[serde(default)]
    pub jwt: JwtConfig,
    #[serde(default)]
    pub password_policy: PasswordPolicy,
    #[serde(default)]
    pub audit: AuditConfig,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct JwtConfig {
    #[serde(default = "default_jwt_algorithm")]
    pub algorithm: String,
    pub secret_key: Option<String>,
    pub private_key_path: Option<String>,
    pub public_key_path: Option<String>,
    #[serde(default = "default_token_expiry")]
    pub token_expiry: String,
}

fn default_jwt_algorithm() -> String {
    "RS256".to_string()
}

fn default_token_expiry() -> String {
    "24h".to_string()
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct PasswordPolicy {
    #[serde(default = "default_min_length")]
    pub min_length: u8,
    #[serde(default = "default_require_uppercase")]
    pub require_uppercase: bool,
    #[serde(default = "default_require_lowercase")]
    pub require_lowercase: bool,
    #[serde(default = "default_require_digits")]
    pub require_digits: bool,
    #[serde(default = "default_require_special_chars")]
    pub require_special_chars: bool,
    #[serde(default = "default_max_age_days")]
    pub max_age_days: u32,
    #[serde(default = "default_history_count")]
    pub history_count: u8,
}

fn default_min_length() -> u8 { 8 }
fn default_require_uppercase() -> bool { true }
fn default_require_lowercase() -> bool { true }
fn default_require_digits() -> bool { true }
fn default_require_special_chars() -> bool { false }
fn default_max_age_days() -> u32 { 90 }
fn default_history_count() -> u8 { 5 }

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct TlsConfig {
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub ca_cert_file: Option<String>,
    #[serde(default)]
    pub client_auth_required: bool,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub enable_json_output: bool,
    pub log_file: Option<String>,
    #[serde(default)]
    pub enable_tracing: bool,
}

fn default_log_level() -> String {
    "INFO".to_string()
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct PathsConfig {
    pub keys_dir: Option<String>,
    pub certs_dir: Option<String>,
    pub temp_dir: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub prometheus_endpoint: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct AuditConfig {
    #[serde(default = "default_audit_backend")]
    pub backend: String,
    pub file_path: Option<String>,
    pub database_url: Option<String>,
    pub kafka: Option<KafkaConfig>,
}

fn default_audit_backend() -> String {
    "FILE".to_string()
}

#[derive(Debug, Deserialize, Serialize)]
pub struct KafkaConfig {
    pub brokers: Vec<String>,
    pub topic: String,
    pub client_id: Option<String>,
}

impl AppConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let content = serde_yaml::to_string(self)?;
        fs::write(path, content)?;
        Ok(())
    }
}