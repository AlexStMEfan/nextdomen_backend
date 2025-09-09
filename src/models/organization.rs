// src/models/organization.rs

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::models::policy::PolicyId;
use chrono::Utc;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    pub domains: Vec<Uuid>,
    pub default_domain_id: Uuid,
    pub policies: Vec<PolicyId>,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
    pub meta: std::collections::HashMap<String, String>,
}