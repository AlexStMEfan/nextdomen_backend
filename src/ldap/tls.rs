// src/ldap/tls.rs

use rustls_pemfile::{certs, pkcs8_private_keys};
use std::io::Cursor;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use rustls;

/// Загружает TLS-конфигурацию из PEM-сертификата и приватного ключа
pub fn load_tls_config(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
    // Парсим цепочку сертификатов
    let cert_chain = certs(&mut Cursor::new(cert_pem))
        .map_err(|_| "Failed to parse certificate PEM")?
        .into_iter()
        .map(rustls::Certificate)
        .collect();

    // Парсим приватный ключ (поддерживаем PKCS#8)
    let mut keys = pkcs8_private_keys(&mut Cursor::new(key_pem))
        .map_err(|_| "Failed to parse private key PEM")?;

    let key = match keys.next() {
        Some(key) => rustls::PrivateKey(key),
        None => return Err("No private key found in key file".into()),
    };

    // Создаём конфигурацию сервера
    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth() // Пока не требуем клиентские сертификаты
        .with_single_cert(cert_chain, key)
        .map_err(|err| format!("Failed to create TLS server config: {}", err))?;

    Ok(Arc::new(config))
}