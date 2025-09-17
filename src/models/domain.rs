// src/models/domain.rs

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::models::sid::SecurityIdentifier;
use crate::models::policy::PolicyId;
use chrono::Utc;
use std::collections::HashMap;

/// Уровень функциональности домена
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum FunctionalLevel {
    Windows2016,
    Windows2022,
    Native,
}

// === Удалены неиспользуемые GUID ===
// Пока не используешь LDAP / wellKnownObjects — можно убрать.
// Верни позже, когда начнёшь работать с контейнерами CN=Users и т.д.

/// Домен Active Directory
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Domain {
    pub id: Uuid,
    pub sid: SecurityIdentifier,
    pub name: String,
    pub dns_name: String,
    pub netbios_name: String,
    pub parent_domain: Option<Uuid>,
    pub child_domains: Vec<Uuid>,
    pub functional_level: FunctionalLevel,
    pub users: Vec<Uuid>,
    pub groups: Vec<Uuid>,
    pub organizational_units: Vec<Uuid>,
    pub policies: Vec<PolicyId>,
    pub enabled: bool,
    pub created_at: chrono::DateTime<Utc>,

    /// Произвольные метаданные
    #[serde(default)]
    pub meta: HashMap<String, String>,
}

impl Domain {
    /// Создать новый домен без системных контейнеров (упрощённая версия)
    pub fn new(
        name: impl Into<String>,
        dns_name: impl Into<String>,
        sid: SecurityIdentifier,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            sid,
            name: name.into(),
            dns_name: dns_name.into(),
            netbios_name: "CORP".to_string(), // Можно задать как параметр
            parent_domain: None,
            child_domains: vec![],
            functional_level: FunctionalLevel::Native,
            users: vec![],
            groups: vec![],
            organizational_units: vec![],
            policies: vec![],
            enabled: true,
            created_at: chrono::Utc::now(),
            meta: HashMap::new(),
        }
    }

    /// Получить DN домена (например, DC=corp,DC=acme,DC=com)
    pub fn dn(&self) -> String {
        self.dns_name
            .split('.')
            .map(|part| format!("DC={}", part))
            .collect::<Vec<_>>()
            .join(",")
    }
}