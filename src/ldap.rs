// src/ldap.rs

use crate::directory_service::DirectoryService;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Arc;
use uuid::Uuid;
use std::collections::HashMap;
use chrono::Utc;

// Простая реализация LDAP (RFC 4511)
// Только bind + search для прототипа

#[derive(Debug)]
pub enum LdapError {
    Io(std::io::Error),
    InvalidRequest,
    AuthenticationFailed,
    NotFound,
    NotImplemented,
}

impl From<std::io::Error> for LdapError {
    fn from(e: std::io::Error) -> Self {
        LdapError::Io(e)
    }
}

impl std::fmt::Display for LdapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LdapError::Io(e) => write!(f, "IO error: {}", e),
            LdapError::InvalidRequest => write!(f, "Invalid LDAP request"),
            LdapError::AuthenticationFailed => write!(f, "Authentication failed"),
            LdapError::NotFound => write!(f, "Not found"),
            LdapError::NotImplemented => write!(f, "Not implemented"),
        }
    }
}

impl std::error::Error for LdapError {}

pub struct LdapServer {
    service: Arc<DirectoryService>,
    listener: TcpListener,
}

impl LdapServer {
    pub async fn bind(service: Arc<DirectoryService>, addr: &str) -> Result<Self, LdapError> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self { service, listener })
    }

    pub async fn run(&self) -> Result<(), LdapError> {
        println!("LDAP server listening on {}", self.listener.local_addr()?);

        loop {
            let (mut socket, _) = self.listener.accept().await?;
            let service = Arc::clone(&self.service);

            tokio::spawn(async move {
                if let Err(e) = handle_client(socket, service).await {
                    eprintln!("LDAP client error: {}", e);
                }
            });
        }
    }
}

async fn handle_client(
    mut socket: tokio::net::TcpStream,
    service: Arc<DirectoryService>,
) -> Result<(), LdapError> {
    let mut buf = [0u8; 1024];

    loop {
        let n = socket.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        // Очень упрощённый парсинг — только первые байты
        // В реальности нужен ASN.1 парсер, но для прототипа — заглушка

        let msg_type = buf[1];
        match msg_type {
            0 => {
                // BIND request (простейшая проверка)
                if n >= 30 && &buf[10..24] == b"jdoe" && &buf[25..29] == b"pass" {
                    // Ответ: BIND RESPONSE (успешно)
                    let response = [
                        0x30, 0x0c,                   // LDAPMessage
                        0x02, 0x01, 0x01,             // messageID
                        0x61, 0x07,                   // bindResponse
                        0x0a, 0x01, 0x00,             // resultCode: success
                        0x04, 0x00,                   // matchedDN
                        0x04, 0x00,                   // diagnosticMessage
                    ];
                    socket.write_all(&response).await?;
                } else {
                    // Ошибка аутентификации
                    let response = [
                        0x30, 0x0c,
                        0x02, 0x01, 0x01,
                        0x61, 0x07,
                        0x0a, 0x01, 0x13, // invalidCredentials
                        0x04, 0x00,
                        0x04, 0x00,
                    ];
                    socket.write_all(&response).await?;
                }
            }
            3 => {
                // SEARCH request (упрощённо)
                // Ищем по sAMAccountName или DN
                let response = vec![
                    // SearchResultEntry
                    0x30, 0x34, // LDAPMessage
                    0x02, 0x01, 0x02, // messageID
                    0x64, 0x2f, // searchResEntry
                    0x04, 0x1d, b'C', b'N', b'=', b'j', b'd', b'o', b'e', b',', b'D', b'C', b'=', b'c', b'o', b'r', b'p', b',', b'D', b'C', b'=', b'a', b'c', b'm', b'e', b',', b'D', b'C', b'=', b'c', b'o', b'm',
                    0x30, 0x0e, // Attributes
                    0x30, 0x0c,
                    0x04, 0x0b, b's', b'A', b'M', b'A', b'c', b'c', b'o', b'u', b'n', b't', b'N', b'a', b'm', b'e',
                    0x04, 0x07, b'j', b'd', b'o', b'e',
                ];
                socket.write_all(&response).await?;

                // SearchDone
                let done = [
                    0x30, 0x0c,
                    0x02, 0x01, 0x02,
                    0x65, 0x07,
                    0x0a, 0x01, 0x00,
                    0x04, 0x00,
                    0x04, 0x00,
                ];
                socket.write_all(&done).await?;
            }
            _ => {
                return Err(LdapError::NotImplemented);
            }
        }
    }

    Ok(())
}