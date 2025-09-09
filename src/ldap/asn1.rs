// src/ldap/mod.rs

pub mod asn1;

use crate::directory_service::DirectoryService;
use asn1::Asn1;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug)]
pub enum LdapError {
    Io(std::io::Error),
    ParseError,
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
            LdapError::ParseError => write!(f, "ASN.1 parse error"),
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
        println!("🔐 LDAP server listening on {}", self.listener.local_addr()?);

        loop {
            let (socket, _) = self.listener.accept().await?;
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
    let mut buf = vec![0u8; 4096];

    loop {
        let n = socket.read(&mut buf).await?;
        if n == 0 { break; }

        let mut parser = asn1::Asn1Parser::new(buf[..n].to_vec());

        if let Some(Asn1::Sequence(mut message)) = parser.parse() {
            if message.len() < 3 { continue; }

            let msg_id = match &message[0] {
                Asn1::Integer(id) => *id as u32,
                _ => continue,
            };

            if let Some(Asn1::Sequence(ref op)) = message.get(2) {
                match op.get(0) {
                    Some(Asn1::OctetString(_)) if op.len() >= 3 => {
                        // BIND request
                        handle_bind(&mut socket, msg_id).await?;
                    }
                    Some(Asn1::Enumerated(3)) => {
                        // SEARCH request
                        handle_search(&mut socket, msg_id, &service, op).await?;
                    }
                    _ => {
                        send_error(&mut socket, msg_id, 12).await?; // unavailable
                    }
                }
            }
        } else {
            send_error(&mut socket, 1, 2).await?; // protocolError
        }
    }

    Ok(())
}

async fn handle_bind(socket: &mut tokio::net::TcpStream, msg_id: u32) -> Result<(), LdapError> {
    // Простой успех (в реальности — проверка DN + пароля)
    let response = build_bind_response(msg_id, 0); // success
    socket.write_all(&response).await?;
    Ok(())
}

async fn handle_search(
    socket: &mut tokio::net::TcpStream,
    msg_id: u32,
    service: &DirectoryService,
    op: &[Asn1],
) -> Result<(), LdapError> {
    // Извлекаем baseObject, filter
    let base = extract_string_from_sequence(op, 0);
    let filter = extract_string_from_sequence(op, 4);

    eprintln!("🔍 LDAP search: base='{}', filter='{}'", base, filter);

    // Отправляем SearchResultEntry (заглушка)
    let entry = build_search_result_entry(msg_id, "CN=jdoe,DC=corp,DC=acme,DC=com");
    socket.write_all(&entry).await?;

    // SearchDone
    let done = build_search_done(msg_id, 0);
    socket.write_all(&done).await?;

    Ok(())
}

fn extract_string_from_sequence(seq: &[Asn1], index: usize) -> String {
    if let Some(Asn1::OctetString(data)) = seq.get(index) {
        String::from_utf8_lossy(data).to_string()
    } else {
        "".to_string()
    }
}

// === ASN.1 Builders ===

fn build_bind_response(msg_id: u32, result_code: u8) -> Vec<u8> {
    let mut w = Vec::new();
    write_sequence(&mut w, |w| {
        write_integer(w, msg_id as i64);
        write_enumerated(w, 1); // bindResponse
        write_sequence(w, |w| {
            write_enumerated(w, result_code); // success = 0
            write_octet_string(w, &[]);
            write_octet_string(w, &[]);
        });
    });
    w
}

fn build_search_result_entry(msg_id: u32, dn: &str) -> Vec<u8> {
    let mut w = Vec::new();
    write_sequence(&mut w, |w| {
        write_integer(w, msg_id as i64);
        write_enumerated(w, 4); // searchResEntry
        write_octet_string(w, dn.as_bytes());
        write_sequence(w, |w| {
            write_sequence(w, |w| {
                write_octet_string(w, b"sAMAccountName");
                write_sequence(w, |w| {
                    write_octet_string(w, b"jdoe");
                });
            });
        });
    });
    w
}

fn build_search_done(msg_id: u32, result_code: u8) -> Vec<u8> {
    let mut w = Vec::new();
    write_sequence(&mut w, |w| {
        write_integer(w, msg_id as i64);
        write_enumerated(w, 5); // searchResDone
        write_enumerated(w, result_code);
        write_octet_string(w, &[]);
        write_octet_string(w, &[]);
    });
    w
}

// === ASN.1 Writers ===

fn write_integer<F>(w: &mut Vec<u8>, mut n: i64) {
    let mut bytes = Vec::new();
    if n == 0 {
        bytes.push(0);
    } else {
        while n > 0 {
            bytes.push((n & 0xFF) as u8);
            n >>= 8;
        }
        if bytes.last().unwrap() >= 0x80 {
            bytes.push(0);
        }
    }
    bytes.reverse();
    write_type_and_length(w, 0x02, bytes.len());
    w.extend(bytes);
}

fn write_enumerated(w: &mut Vec<u8>, n: u32) {
    let mut bytes = Vec::new();
    while n > 0 {
        bytes.push((n & 0xFF) as u8);
        n >>= 8;
    }
    if bytes.is_empty() { bytes.push(0); }
    if bytes.last().unwrap() >= 0x80 { bytes.push(0); }
    bytes.reverse();
    write_type_and_length(w, 0x0A, bytes.len());
    w.extend(bytes);
}

fn write_octet_string(w: &mut Vec<u8>, data: &[u8]) {
    write_type_and_length(w, 0x04, data.len());
    w.extend(data);
}

fn write_sequence<F>(w: &mut Vec<u8>, f: F) where F: FnOnce(&mut Vec<u8>) {
    let mut body = Vec::new();
    f(&mut body);
    write_type_and_length(w, 0x30, body.len());
    w.extend(body);
}

fn write_type_and_length(w: &mut Vec<u8>, tag: u8, len: usize) {
    w.push(tag);
    if len < 0x80 {
        w.push(len as u8);
    } else {
        let mut n = len;
        let mut bytes = Vec::new();
        while n > 0 {
            bytes.push((n & 0xFF) as u8);
            n >>= 8;
        }
        w.push(0x80 | (bytes.len() as u8));
        w.extend(bytes.iter().rev());
    }
}