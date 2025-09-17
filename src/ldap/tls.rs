// src/ldap/tls.rs

use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use rustls;

pub fn load_tls_config_from_files(
    cert_path: &str,
    key_path: &str,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let cert_file = &mut BufReader::new(File::open(cert_path)?);
    let key_file = &mut BufReader::new(File::open(key_path)?);

    let cert_chain = certs(cert_file)
        .map_err(|_| "Failed to parse certificate PEM")?
        .into_iter()
        .map(rustls::Certificate)
        .collect();

    let mut keys = pkcs8_private_keys(key_file)
        .map_err(|_| "Failed to parse private key PEM")?;

    let key = keys.next()
        .ok_or("No private key found")?
        .into();

    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|err| format!("TLS config error: {}", err))?;

    Ok(Arc::new(config))
}