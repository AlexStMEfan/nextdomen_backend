// src/models/group.rs

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::models::sid::SecurityIdentifier;
use chrono::Utc;
use bitflags::bitflags;
use std::collections::HashMap;

// ========================================
// 🛡️ GroupTypeFlags — с гарантией Clone, Copy
// ========================================

bitflags! {
    /// Флаги типа группы: SECURITY, DISTRIBUTION, BUILTIN
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    pub struct GroupTypeFlags: u32 {
        const SECURITY     = 0x8000_0000;
        const DISTRIBUTION = 0x0000_0001;
        const BUILTIN      = 0x0000_0002;
    }
}

// Ручная реализация Serialize
impl Serialize for GroupTypeFlags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u32(self.bits())
    }
}

// Ручная реализация Deserialize
impl<'de> Deserialize<'de> for GroupTypeFlags {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bits = u32::deserialize(deserializer)?;
        Self::from_bits(bits).ok_or_else(|| {
            serde::de::Error::custom(format!("Invalid GroupTypeFlags: 0x{:08X}", bits))
        })
    }
}

// Кастомный Debug — красивый вывод
impl std::fmt::Debug for GroupTypeFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        if self.contains(Self::SECURITY)     { parts.push("SECURITY"); }
        if self.contains(Self::DISTRIBUTION) { parts.push("DISTRIBUTION"); }
        if self.contains(Self::BUILTIN)      { parts.push("BUILTIN"); }
        if parts.is_empty() { parts.push("empty"); }
        write!(f, "GroupTypeFlags({})", parts.join(" | "))
    }
}

// ========================================
// 🌐 GroupScope — область действия
// ========================================

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupScope {
    DomainLocal,
    Global,
    Universal,
}

// ========================================
// 👥 Group — основная структура
// ========================================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Group {
    pub id: Uuid,
    pub sid: SecurityIdentifier,
    pub name: String,
    pub sam_account_name: String,
    pub description: Option<String>,
    pub members: Vec<Uuid>,
    pub domain_id: Uuid,
    pub scope: GroupScope,
    pub type_flags: GroupTypeFlags,
    pub created_at: chrono::DateTime<Utc>,
    pub meta: HashMap<String, String>,
}

// ========================================
// ✅ Реализации
// ========================================

impl Group {
    pub fn new(
        name: String,
        sam_account_name: String,
        domain_id: Uuid,
        type_flags: GroupTypeFlags,
        scope: GroupScope,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            sid: SecurityIdentifier::new_nt_authority(512),
            name,
            sam_account_name,
            description: None,
            members: Vec::new(),
            domain_id,
            scope,
            type_flags,
            created_at: Utc::now(),
            meta: HashMap::new(),
        }
    }

    #[allow(dead_code)]
    pub fn is_security_group(&self) -> bool {
        self.type_flags.contains(GroupTypeFlags::SECURITY)
    }

    #[allow(dead_code)]
    pub fn is_builtin(&self) -> bool {
        self.type_flags.contains(GroupTypeFlags::BUILTIN)
    }

    #[allow(dead_code)]
    pub fn add_member(&mut self, user_id: Uuid) {
        if !self.members.contains(&user_id) {
            self.members.push(user_id);
        }
    }

    #[allow(dead_code)]
    pub fn remove_member(&mut self, user_id: &Uuid) {
        self.members.retain(|id| id != user_id);
    }

    #[allow(dead_code)]
    pub fn to_ldap_entry(&self, dn: &str) -> HashMap<String, Vec<String>> {
        let mut entry = HashMap::new();

        entry.insert("objectClass".to_string(), vec![
            "top".to_string(),
            "group".to_string(),
        ]);
        entry.insert("distinguishedName".to_string(), vec![dn.to_string()]);
        entry.insert("cn".to_string(), vec![self.name.clone()]);
        entry.insert("sAMAccountName".to_string(), vec![self.sam_account_name.clone()]);
        entry.insert("name".to_string(), vec![self.name.clone()]);
        entry.insert("objectSid".to_string(), vec![self.sid.to_string()]);

        if let Some(desc) = &self.description {
            entry.insert("description".to_string(), vec![desc.clone()]);
        }

        // groupType: зависит от флагов
        let mut group_type = 0u32;
        if self.type_flags.contains(GroupTypeFlags::SECURITY) {
            group_type |= 0x0000_0008; // SECURITY_ENABLED
        }
        if self.type_flags.contains(GroupTypeFlags::BUILTIN) {
            // Не влияет на groupType напрямую
        }
        entry.insert("groupType".to_string(), vec![group_type.to_string()]);

        entry.insert("whenCreated".to_string(), vec![
            format_ldap_time(&self.created_at)
        ]);

        entry
    }

    pub fn get_primary_group_token(&self) -> SecurityIdentifier {
        // primaryGroupToken = domain SID + group RID
        // Например: S-1-5-21-...-513
        let mut sid = self.sid.clone();
        // Удаляем последний RID (если это встроенный SID)
        if let Some(_rid) = sid.sub_authorities.pop() {
            // Оставляем домен SID
        }
        sid.sub_authorities.push(self.get_rid());
        sid
    }

    /// Получить RID группы (например, 513 для Domain Users)
    pub fn get_rid(&self) -> u32 {
        // В реальности — зависит от типа
        match self.type_flags {
            f if f.contains(GroupTypeFlags::BUILTIN) => 512 + self.id.as_bytes()[0] as u32 % 100,
            _ => 1000 + self.id.as_u128() as u32 % 1_000_000,
        }
    }
}

// Вспомогательная функция для времени
#[allow(dead_code)]
fn format_ldap_time(dt: &chrono::DateTime<Utc>) -> String {
    dt.format("%Y%m%d%H%M%S.0Z").to_string()
}