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

// GUID well-known объектов (из реального Active Directory)
pub const GUID_USERS_CONTAINER: &str = "AA312825768811D1ADED00C04FD8D5CD";
pub const GUID_COMPUTERS_CONTAINER: &str = "AA312826768811D1ADED00C04FD8D5CD";
pub const GUID_DOMAIN_CONTROLLERS_CONTAINER: &str = "AA312827768811D1ADED00C04FD8D5CD";
pub const GUID_PROGRAM_DATA_CONTAINER: &str = "0AC9503533DE45899044C51926617F76";
pub const GUID_FOREIGN_SECURITY_PRINCIPALS_CONTAINER: &str = "E48D0154BCC811D19D7A00C04FD8D5CD";

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

    /// wellKnownObjects — сопоставление GUID → DN
    /// Например: "AA312825768811D1ADED00C04FD8D5CD" → "CN=Users,DC=corp,DC=acme,DC=com"
    #[serde(default)]
    pub well_known_objects: HashMap<String, String>,

    /// Произвольные метаданные
    #[serde(default)]
    pub meta: HashMap<String, String>,
}

impl Domain {
    /// Создать домен с системными well-known контейнерами
    pub fn new_with_defaults(
        name: String,
        dns_name: String,
        sid: SecurityIdentifier,
    ) -> Self {
        let mut domain = Self {
            id: Uuid::new_v4(),
            sid,
            name,
            dns_name,
            netbios_name: "ACME".to_string(),
            parent_domain: None,
            child_domains: vec![],
            functional_level: FunctionalLevel::Native,
            users: vec![],
            groups: vec![],
            organizational_units: vec![],
            policies: vec![],
            enabled: true,
            created_at: chrono::Utc::now(),
            well_known_objects: HashMap::new(),
            meta: HashMap::new(),
        };

        domain.create_default_containers();
        domain
    }

    /// Создать стандартные well-known объекты (CN=Users, CN=Computers и т.д.)
    pub fn create_default_containers(&mut self) {
        let domain_dn = self.dn();

        // CN=Users
        let users_dn = format!("CN=Users,{}", domain_dn);
        self.well_known_objects.insert(GUID_USERS_CONTAINER.to_string(), users_dn);

        // CN=Computers
        let computers_dn = format!("CN=Computers,{}", domain_dn);
        self.well_known_objects.insert(GUID_COMPUTERS_CONTAINER.to_string(), computers_dn);

        // CN=Domain Controllers
        let dc_dn = format!("CN=Domain Controllers,{}", domain_dn);
        self.well_known_objects.insert(GUID_DOMAIN_CONTROLLERS_CONTAINER.to_string(), dc_dn);

        // CN=Program Data
        let program_data_dn = format!("CN=Program Data,{}", domain_dn);
        self.well_known_objects.insert(GUID_PROGRAM_DATA_CONTAINER.to_string(), program_data_dn);

        // CN=ForeignSecurityPrincipals
        let fsp_dn = format!("CN=ForeignSecurityPrincipals,{}", domain_dn);
        self.well_known_objects.insert(GUID_FOREIGN_SECURITY_PRINCIPALS_CONTAINER.to_string(), fsp_dn);
    }

    /// Получить DN домена (например, DC=corp,DC=acme,DC=com)
    pub fn dn(&self) -> String {
        self.dns_name
            .split('.')
            .map(|part| format!("DC={}", part))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Преобразовать домен в LDAP-запись (domainDNS)
    #[allow(dead_code)]
    pub fn to_ldap_entry(&self) -> HashMap<String, Vec<String>> {
        let mut entry = HashMap::new();
        let dn = self.dn();

        entry.insert("objectClass".to_string(), vec![
            "top".to_string(),
            "domain".to_string(),
            "domainDNS".to_string(),
        ]);
        entry.insert("distinguishedName".to_string(), vec![dn.clone()]);
        entry.insert("dc".to_string(), vec![self.dns_name.split('.').next().unwrap_or("").to_string()]);
        entry.insert("name".to_string(), vec![self.netbios_name.clone()]);
        entry.insert("uSNCreated".to_string(), vec!["0".to_string()]); // заглушка
        entry.insert("objectSid".to_string(), vec![self.sid.to_string()]);

        // wellKnownObjects: B:32:<GUID>:<DN>
        let mut wko = Vec::new();
        for (guid, real_dn) in &self.well_known_objects {
            wko.push(format!("B:32:{}:{}", guid, real_dn));
        }
        entry.insert("wellKnownObjects".to_string(), wko);

        // Функциональный уровень
        let fl = match self.functional_level {
            FunctionalLevel::Windows2016 => "7",
            FunctionalLevel::Windows2022 => "8",
            FunctionalLevel::Native => "4", // упрощённо
        };
        entry.insert("domainFunctionality".to_string(), vec![fl.to_string()]);
        entry.insert("forestFunctionality".to_string(), vec![fl.to_string()]);
        entry.insert("domainControllerFunctionality".to_string(), vec![fl.to_string()]);

        // whenCreated
        entry.insert("whenCreated".to_string(), vec![
            format_ldap_time(&self.created_at)
        ]);

        // meta — кастомные атрибуты
        for (k, v) in &self.meta {
            entry.insert(k.clone(), vec![v.clone()]);
        }

        entry
    }
}

/// Форматирует время в LDAP Generalized Time (YYYYMMDDHHMMSS.0Z)
#[allow(dead_code)]
fn format_ldap_time(dt: &chrono::DateTime<Utc>) -> String {
    dt.format("%Y%m%d%H%M%S.0Z").to_string()
}