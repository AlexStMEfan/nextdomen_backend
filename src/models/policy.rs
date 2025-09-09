// src/models/policy.rs

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::models::sid::SecurityIdentifier;
use chrono::Utc;

pub type PolicyId = Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PolicyType {
    Security,
    Registry,
    Script,
    Network,
    Software,
    FolderRedirection,
    Custom(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PolicyTarget {
    Domain(Uuid),
    OrganizationalUnit(Uuid),
    Group(Uuid),
    User(Uuid),
    All,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum PolicyValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    List(Vec<PolicyValue>),
    Json(serde_json::Value),
    Binary(Vec<u8>),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SidOrId {
    Sid(SecurityIdentifier),
    Id(Uuid),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GroupPolicy {
    pub id: PolicyId,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub version: u32,
    pub policy_type: PolicyType,
    pub target: PolicyTarget,
    pub settings: std::collections::HashMap<String, PolicyValue>,
    pub enabled: bool,
    pub enforced: bool,
    pub order: u32,
    pub security_filtering: Vec<SidOrId>,
    pub wmi_filter: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
    pub linked_to: Vec<Uuid>, // OU или Domain ID
}