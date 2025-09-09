// src/models/ou.rs

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::models::policy::PolicyId;
use chrono::Utc;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OrganizationalUnit {
    pub id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,

    /// DN: например, OU=IT,DC=corp,DC=com
    pub dn: String,

    /// Родительский OU или домен
    pub parent: Option<Uuid>,

    /// Объекты в этом OU
    pub users: Vec<Uuid>,
    pub groups: Vec<Uuid>,
    pub child_ous: Vec<Uuid>,

    /// Привязанные групповые политики
    pub linked_gpos: Vec<PolicyId>,

    /// Блокировать наследование политик от родителя?
    pub block_inheritance: bool,

    /// Политики применяются, даже если выше стоит `block_inheritance`
    pub enforced: bool,

    // 🔽 Атрибуты для LDAP-совместимости
    #[serde(default)]
    pub gplink: String, // Формат: "[{GUID};3][{GUID2};2]"

    #[serde(default)]
    pub gpoptions: u32, // 0 = no block, 1 = block inheritance

    /// Произвольные метаданные
    pub meta: HashMap<String, String>,

    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

impl OrganizationalUnit {
    /// Обновить gPLink на основе linked_gpos
    pub fn update_gplink(&mut self) {
        let mut link = String::new();
        for gpo_id in &self.linked_gpos {
            // Флаг: 1 = enabled, 2 = enabled + enforced
            let flag = if self.enforced { 2 } else { 1 };
            link.push_str(&format!("[{};{}]", gpo_id, flag));
        }
        self.gplink = link;
    }

    /// Обновить gpoptions на основе block_inheritance
    pub fn update_gpoptions(&mut self) {
        self.gpoptions = if self.block_inheritance { 1 } else { 0 };
    }

    /// Создать пустой OU с правильными атрибутами
    pub fn new(name: String, dn: String, parent: Option<Uuid>) -> Self {
        let mut ou = Self {
            id: Uuid::new_v4(),
            name,
            display_name: None,
            description: None,
            dn,
            parent,
            users: vec![],
            groups: vec![],
            child_ous: vec![],
            linked_gpos: vec![],
            block_inheritance: false,
            enforced: false,
            gplink: String::new(),
            gpoptions: 0,
            meta: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        ou.update_gplink();
        ou.update_gpoptions();
        ou
    }

    /// Преобразовать OU в LDAP-запись
        #[allow(dead_code)]
    pub fn to_ldap_entry(&self) -> HashMap<String, Vec<String>> {
        let mut entry = HashMap::new();

        entry.insert("objectClass".to_string(), vec![
            "top".to_string(),
            "organizationalUnit".to_string(),
        ]);
        entry.insert("distinguishedName".to_string(), vec![self.dn.clone()]);
        entry.insert("ou".to_string(), vec![self.name.clone()]);
        entry.insert("name".to_string(), vec![self.name.clone()]);

        if let Some(display_name) = &self.display_name {
            entry.insert("displayName".to_string(), vec![display_name.clone()]);
        }
        if let Some(description) = &self.description {
            entry.insert("description".to_string(), vec![description.clone()]);
        }

        // gPLink и gPOptions — ключевые для GPO
        entry.insert("gPLink".to_string(), vec![self.gplink.clone()]);
        entry.insert("gPOptions".to_string(), vec![self.gpoptions.to_string()]);

        // whenCreated и whenChanged
        entry.insert("whenCreated".to_string(), vec![
            format_ldap_time(&self.created_at)
        ]);
        entry.insert("whenChanged".to_string(), vec![
            format_ldap_time(&self.updated_at)
        ]);

        // meta — кастомные атрибуты
        for (k, v) in &self.meta {
            entry.insert(k.clone(), vec![v.clone()]);
        }

        entry
    }
}

/// Форматирует время в LDAP Generalized Time (YYYYMMDDHHMMSS.0Z)
fn format_ldap_time(dt: &chrono::DateTime<Utc>) -> String {
    dt.format("%Y%m%d%H%M%S.0Z").to_string()
}