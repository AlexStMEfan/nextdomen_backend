// src/ldap/mod.rs

pub mod asn1;
pub mod filter;

use crate::directory_service::DirectoryService;
use crate::models::{User, Domain, OrganizationalUnit};
use asn1::Asn1;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;
use chrono::Utc;

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
    let base = extract_string_from_sequence(op, 0);
    let scope = extract_enumerated_from_sequence(op, 1); // 0=base, 1=one, 2=subtree
    let filter_bytes = if let Some(Asn1::OctetString(data)) = op.get(4) {
        data
    } else {
        return send_error(socket, msg_id, 2).await; // protocolError
    };

    let filter_str = String::from_utf8_lossy(filter_bytes);
    eprintln!("🔍 LDAP filter: {}", filter_str);

    let filter = match filter::Filter::parse(&filter_str) {
        Ok(f) => f,
        Err(_) => return send_error(socket, msg_id, 21).await, // invalidAttributeSyntax
    };

    // 🔽 Используем заглушку для домена (в реальности — получи из базы)
    let domain = Domain::new_with_defaults(
        "Acme Corp".to_string(),
        "corp.acme.com".to_string(),
        SecurityIdentifier::new_nt_authority(512),
    );
    let domain_dn = domain.dn();

    // 🔽 Получим всех пользователей (в реальности — через индекс)
    // Пока заглушка: получи список user_id из базы
    let all_user_ids = vec![]; // service.get_all_user_ids().await?;

    for user_id in all_user_ids {
        let user = match service.get_user(user_id).await? {
            Some(u) => u,
            None => continue,
        };

        // Проверяем фильтр с сервисом (для tokenGroups)
        if !filter.matches_user_with_service(&user, service).await? {
            continue;
        }

        let dn = DirectoryService::generate_user_dn(&user, &domain);
        let entry = match user.to_ldap_entry(&dn, service).await {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Собираем ASN.1 ответ
        let mut attrs = Vec::new();
        for (attr, values) in entry {
            let mut vals = Vec::new();
            for v in values {
                vals.push(Asn1::OctetString(v.into_bytes()));
            }
            attrs.push(Asn1::Sequence(vec![
                Asn1::OctetString(attr.into_bytes()),
                Asn1::Sequence(vals),
            ]));
        }

        let response = build_search_result_entry(msg_id, &dn, &attrs);
        socket.write_all(&response).await?;
    }

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

fn extract_enumerated_from_sequence(seq: &[Asn1], index: usize) -> u32 {
    if let Some(Asn1::Enumerated(n)) = seq.get(index) {
        *n
    } else {
        0
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

fn build_search_result_entry(msg_id: u32, dn: &str, attributes: &[Asn1]) -> Vec<u8> {
    let mut w = Vec::new();
    write_sequence(&mut w, |w| {
        write_integer(w, msg_id as i64);
        write_enumerated(w, 4); // searchResEntry
        write_octet_string(w, dn.as_bytes());
        write_sequence(w, |w| {
            for attr in attributes {
                write_sequence(w, |w| {
                    if let Asn1::Sequence(ref inner) = attr {
                        if let Some(Asn1::OctetString(name)) = inner.get(0) {
                            write_octet_string(w, name);
                        }
                        if let Some(Asn1::Sequence(vals)) = inner.get(1) {
                            write_sequence(w, |w| {
                                for val in vals {
                                    if let Asn1::OctetString(data) = val {
                                        write_octet_string(w, data);
                                    }
                                }
                            });
                        }
                    }
                });
            }
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

fn write_integer(w: &mut Vec<u8>, mut n: i64) {
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
    let mut n = n;
    while n > 0 {
        bytes.push((n & 0xFF) as u8);
        n >>= 8;
    }
    if bytes.is_empty() {
        bytes.push(0);
    }
    if bytes.last().unwrap() >= 0x80 {
        bytes.push(0);
    }
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

// === Вспомогательные функции ===

fn send_error(socket: &mut tokio::net::TcpStream, msg_id: u32, code: u8) -> Result<(), LdapError> {
    let response = build_search_done(msg_id, code);
    socket.write_all(&response)?;
    Ok(())
}