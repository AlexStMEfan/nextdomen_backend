// src/models/well_known.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// GUID well-known объектов из Active Directory
pub mod guid {
    pub const USERS_CONTAINER: &str = "AA312825768811D1ADED00C04FD8D5CD";
    pub const COMPUTERS_CONTAINER: &str = "AA312826768811D1ADED00C04FD8D5CD";
    pub const DOMAIN_CONTROLLERS_CONTAINER: &str = "AA312827768811D1ADED00C04FD8D5CD";
    pub const PROGRAM_DATA_CONTAINER: &str = "0AC9503533DE45899044C51926617F76";
    pub const FOREIGN_SECURITY_PRINCIPALS_CONTAINER: &str = "E48D0154BCC811D19D7A00C04FD8D5CD";
}

/// Well-Known объекты домена
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WellKnownContainers {
    containers: HashMap<String, String>, // GUID → DN
}

impl WellKnownContainers {
    pub fn new(domain_dn: &str) -> Self {
        let mut containers = HashMap::new();

        // CN=Users
        containers.insert(
            guid::USERS_CONTAINER.to_string(),
            format!("CN=Users,{}", domain_dn),
        );

        // CN=Computers
        containers.insert(
            guid::COMPUTERS_CONTAINER.to_string(),
            format!("CN=Computers,{}", domain_dn),
        );

        // CN=Domain Controllers
        containers.insert(
            guid::DOMAIN_CONTROLLERS_CONTAINER.to_string(),
            format!("CN=Domain Controllers,{}", domain_dn),
        );

        // CN=Program Data
        containers.insert(
            guid::PROGRAM_DATA_CONTAINER.to_string(),
            format!("CN=Program Data,{}", domain_dn),
        );

        // CN=ForeignSecurityPrincipals
        containers.insert(
            guid::FOREIGN_SECURITY_PRINCIPALS_CONTAINER.to_string(),
            format!("CN=ForeignSecurityPrincipals,{}", domain_dn),
        );

        Self { containers }
    }

    /// Получить DN по GUID
    pub fn get(&self, guid: &str) -> Option<&String> {
        self.containers.get(guid)
    }

    /// Список всех пар (GUID, DN)
    pub fn list(&self) -> &HashMap<String, String> {
        &self.containers
    }

    /// Проверить, принадлежит ли DN well-known контейнеру
    pub fn is_well_known_dn(&self, dn: &str) -> bool {
        self.containers.values().any(|known_dn| known_dn == dn)
    }
}