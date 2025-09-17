// src/events.rs

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::Utc;
use tokio::sync::broadcast;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuditEvent {
    pub id: Uuid,
    pub action: String,
    pub actor_id: Option<Uuid>,
    pub target_id: Option<Uuid>,
    pub ip_addr: Option<String>,
    pub metadata: std::collections::HashMap<String, String>,
    pub timestamp: chrono::DateTime<Utc>,
}

pub struct EventHub {
    sender: broadcast::Sender<AuditEvent>,
}

impl EventHub {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(1000);
        Self { sender }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AuditEvent> {
        self.sender.subscribe()
    }

    pub fn emit(&self, event: AuditEvent) {
        let _ = self.sender.send(event); // игнорируем, если нет получателей
    }
}

#[macro_export]
macro_rules! audit_log {
    ($hub:expr, $action:expr, $actor:expr, $target:expr, $ip:expr, $($key:expr => $value:expr),*) => {
        {
            let mut meta = std::collections::HashMap::new();
            $(
                meta.insert($key.to_string(), $value.to_string());
            )*
            let event = AuditEvent {
                id: Uuid::new_v4(),
                action: $action.to_string(),
                actor_id: $actor,
                target_id: $target,
                ip_addr: $ip,
                metadata: meta,
                timestamp: Utc::now(),
            };
            $hub.emit(event);
        }
    };
}

// Пример использования:
// audit_log!(hub, "user.login.success", Some(user.id), None, Some(ip), "method" => "password");