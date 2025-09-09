// src/models/user.rs

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::models::sid::SecurityIdentifier;
use crate::models::password::PasswordHash;
use crate::models::MfaMethod;
use chrono::Utc;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub sid: SecurityIdentifier,
    pub username: String,
    pub user_principal_name: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub surname: Option<String>,
    pub password_hash: PasswordHash,
    pub password_expires: Option<chrono::DateTime<Utc>>,
    pub last_password_change: chrono::DateTime<Utc>,
    pub lockout_until: Option<chrono::DateTime<Utc>>,
    pub failed_logins: u32,
    pub enabled: bool,
    pub mfa_enabled: bool,
    pub mfa_methods: Vec<MfaMethod>,
    pub domains: Vec<Uuid>,
    pub groups: Vec<Uuid>,
    pub organizational_unit: Option<Uuid>,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
    pub last_login: Option<chrono::DateTime<Utc>>,
    pub profile_path: Option<String>,
    pub script_path: Option<String>,
    pub meta: HashMap<String, String>,

    /// ID основной группы (например, 513 = Domain Users)
    pub primary_group_id: Option<u32>,
}
    #[allow(dead_code)]
impl User {
    /// Преобразовать пользователя в LDAP-запись
    pub async fn to_ldap_entry(
        &self,
        dn: &str,
        service: &crate::directory_service::DirectoryService,
    ) -> Result<HashMap<String, Vec<String>>, crate::directory_service::DirectoryError> {
        let mut entry = HashMap::new();

        entry.insert("objectClass".to_string(), vec![
            "top".to_string(),
            "person".to_string(),
            "organizationalPerson".to_string(),
            "user".to_string(),
        ]);
        entry.insert("distinguishedName".to_string(), vec![dn.to_string()]);
        entry.insert("cn".to_string(), vec![
            self.display_name.as_deref().unwrap_or(&self.username).to_string()
        ]);
        entry.insert("sAMAccountName".to_string(), vec![self.username.clone()]);
        entry.insert("userPrincipalName".to_string(), vec![self.user_principal_name.clone()]);
        entry.insert("uid".to_string(), vec![self.username.clone()]);
        entry.insert("name".to_string(), vec![
            self.display_name.as_deref().unwrap_or(&self.username).to_string()
        ]);

        if let Some(email) = &self.email {
            entry.insert("mail".to_string(), vec![email.clone()]);
        }
        if let Some(given_name) = &self.given_name {
            entry.insert("givenName".to_string(), vec![given_name.clone()]);
        }
        if let Some(surname) = &self.surname {
            entry.insert("sn".to_string(), vec![surname.clone()]);
        }

        entry.insert("objectSid".to_string(), vec![self.sid.to_string()]);

        // accountExpires: 0 = never, 9223372036854775807 = disabled
        entry.insert("accountExpires".to_string(), vec![
            if self.enabled { "0" } else { "9223372036854775807" }.to_string()
        ]);

        // userAccountControl: 512 = enabled, 514 = disabled
        let uac = if self.enabled { 512 } else { 514 };
        entry.insert("userAccountControl".to_string(), vec![uac.to_string()]);

        entry.insert("whenCreated".to_string(), vec![
            format_ldap_time(&self.created_at)
        ]);
        entry.insert("whenChanged".to_string(), vec![
            format_ldap_time(&self.updated_at)
        ]);

        if let Some(last_login) = &self.last_login {
            entry.insert("lastLogon".to_string(), vec![format_ldap_time(last_login)]);
        }

        if let Some(profile_path) = &self.profile_path {
            entry.insert("profilePath".to_string(), vec![profile_path.clone()]);
        }
        if let Some(script_path) = &self.script_path {
            entry.insert("scriptPath".to_string(), vec![script_path.clone()]);
        }

        // 🔽 memberOf
        let groups = service.find_groups_by_member(self.id).await?;
        let mut member_of = Vec::new();
        for group in &groups {
            let domain_dn = "DC=corp,DC=acme,DC=com"; // можно улучшить
            let group_dn = format!("CN={},{}", group.name, domain_dn);
            member_of.push(group_dn);
        }
        if !member_of.is_empty() {
            entry.insert("memberOf".to_string(), member_of);
        }

        // 🔽 primaryGroupToken
        if let Some(primary_id) = self.primary_group_id {
            if let Some(group) = service.find_group_by_rid(primary_id).await? {
                let token_sid = group.get_primary_group_token();
                entry.insert("primaryGroupToken".to_string(), vec![token_sid.to_string()]);
            }
        }

        // 🔽 tokenGroups — все группы, в которых состоит пользователь
        match service.get_token_groups(self.id).await {
            Ok(sids) => {
                let tokens: Vec<String> = sids.into_iter().map(|sid| sid.to_string()).collect();
                if !tokens.is_empty() {
                    entry.insert("tokenGroups".to_string(), tokens);
                }
            }
            Err(_) => {}
        }

        // meta — кастомные атрибуты
        for (k, v) in &self.meta {
            entry.insert(k.clone(), vec![v.clone()]);
        }

        Ok(entry)
    }
}

/// Форматирует время в LDAP Generalized Time (YYYYMMDDHHMMSS.0Z)
fn format_ldap_time(dt: &chrono::DateTime<Utc>) -> String {
    dt.format("%Y%m%d%H%M%S.0Z").to_string()
}