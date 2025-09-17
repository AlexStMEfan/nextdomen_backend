// src/domain_controller.rs

use crate::directory_service::{DirectoryService, DirectoryError};
use crate::models::{Domain, User, Group, OrganizationalUnit};
use crate::models::well_known::WellKnownContainers;
use uuid::Uuid;
use chrono::Utc;
use std::sync::Arc;

/// Контроллер домена — управляет жизненным циклом домена и системными объектами
pub struct DomainController {
    service: Arc<DirectoryService>,
}

impl DomainController {
    pub fn new(service: Arc<DirectoryService>) -> Self {
        Self { service }
    }

    /// Инициализировать новый домен с системными контейнерами
    pub async fn bootstrap_domain(
        &self,
        name: String,
        dns_name: String,
    ) -> Result<Domain, DirectoryError> {
        use crate::models::sid::SecurityIdentifier;

        let sid = SecurityIdentifier::new_nt_authority(500); // S-1-5-21-...-500
        let domain = Domain {
            id: Uuid::new_v4(),
            sid,
            name,
            dns_name,
            netbios_name: "CORP".to_string(),
            parent_domain: None,
            child_domains: vec![],
            functional_level: crate::models::domain::FunctionalLevel::Native,
            users: vec![],
            groups: vec![],
            organizational_units: vec![],
            policies: vec![],
            enabled: true,
            created_at: Utc::now(),
            meta: std::collections::HashMap::new(),
        };

        // Сохраняем домен
        self.service.store(format!("domain:{}", domain.id), &domain).await?;

        // Создаём well-known контейнеры
        let wk = WellKnownContainers::new(&domain.dn());

        for (guid, dn) in wk.list() {
            let ou = OrganizationalUnit::new(
                extract_cn(dn).unwrap_or("Unknown").to_string(),
                dn.clone(),
                None,
            );
            self.service.create_ou(&ou).await?;
        }

        // Создаём группу "Domain Users"
        let domain_users = Group::new(
            "Domain Users".to_string(),
            "DOMAIN USERS".to_string(),
            domain.id,
            crate::models::group::GroupTypeFlags::SECURITY,
            crate::models::group::GroupScope::Global,
        );
        self.service.create_group(&domain_users).await?;

        // Создаём группу "Domain Admins"
        let domain_admins = Group::new(
            "Domain Admins".to_string(),
            "DOMAIN ADMINS".to_string(),
            domain.id,
            crate::models::group::GroupTypeFlags::SECURITY,
            crate::models::group::GroupScope::Global,
        );
        self.service.create_group(&domain_admins).await?;

        // Логируем инициализацию
        self.service.log_action(
            "bootstrap_domain",
            &format!("name={}, dns={}", domain.name, domain.dns_name),
            None,
        ).await?;

        Ok(domain)
    }

    /// Найти домен по DNS-имени
    pub async fn find_domain_by_dns(&self, dns_name: &str) -> Result<Option<Domain>, DirectoryError> {
        let domains: Vec<Uuid> = self.service.load("all_domains_index").await?.unwrap_or_default();
        for id in domains {
            let key = format!("domain:{}", id);
            if let Some(domain) = self.service.load::<Domain>(&key).await? {
                if domain.dns_name == dns_name {
                    return Ok(Some(domain));
                }
            }
        }
        Ok(None)
    }
}

/// Вспомогательная функция: извлечь CN из DN
fn extract_cn(dn: &str) -> Option<&str> {
    dn.strip_prefix("CN=")
        .and_then(|s| s.split(',').next())
}