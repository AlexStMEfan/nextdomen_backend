// src/models/policy.rs

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::models::sid::SecurityIdentifier;
use chrono::{Utc, DateTime};

/// Уникальный ID политики
pub type PolicyId = Uuid;

/// Тип групповой политики
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "type", content = "value")]
pub enum PolicyType {
    Security,
    Registry,
    Script,
    Network,
    Software,
    FolderRedirection,
    Custom(String),
}

impl Default for PolicyType {
    fn default() -> Self {
        Self::Custom("Custom".to_string())
    }
}

/// Цель применения политики
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(tag = "type", content = "id")]
pub enum PolicyTarget {
    #[default]
    All,
    Domain(Uuid),
    OrganizationalUnit(Uuid),
    Group(Uuid),
    User(Uuid),
}

impl PolicyTarget {
    pub fn id(&self) -> Option<Uuid> {
        match self {
            PolicyTarget::Domain(id) => Some(*id),
            PolicyTarget::OrganizationalUnit(id) => Some(*id),
            PolicyTarget::Group(id) => Some(*id),
            PolicyTarget::User(id) => Some(*id),
            PolicyTarget::All => None,
        }
    }

    pub fn is_all(&self) -> bool {
        matches!(self, PolicyTarget::All)
    }
}

/// Значение параметра политики (поддержка вложенных структур)
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum PolicyValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    List(Vec<PolicyValue>),
    Json(serde_json::Value),
    Binary(Vec<u8>),
}

impl From<String> for PolicyValue {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<&str> for PolicyValue {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

impl From<i64> for PolicyValue {
    fn from(n: i64) -> Self {
        Self::Integer(n)
    }
}

impl From<bool> for PolicyValue {
    fn from(b: bool) -> Self {
        Self::Boolean(b)
    }
}

impl From<Vec<PolicyValue>> for PolicyValue {
    fn from(v: Vec<PolicyValue>) -> Self {
        Self::List(v)
    }
}

impl From<serde_json::Value> for PolicyValue {
    fn from(v: serde_json::Value) -> Self {
        Self::Json(v)
    }
}

impl From<Vec<u8>> for PolicyValue {
    fn from(v: Vec<u8>) -> Self {
        Self::Binary(v)
    }
}

/// Фильтр безопасности: SID или ID объекта
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum SidOrId {
    Sid(SecurityIdentifier),
    Id(Uuid),
}

impl SidOrId {
    pub fn matches_sid(&self, sid: &SecurityIdentifier) -> bool {
        match self {
            SidOrId::Sid(policy_sid) => policy_sid == sid,
            SidOrId::Id(_) => false,
        }
    }
}

/// Групповая политика (GPO)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GroupPolicy {
    /// Уникальный ID
    pub id: PolicyId,
    /// Имя политики (для отображения)
    pub name: String,
    /// Отображаемое имя
    pub display_name: Option<String>,
    /// Описание
    #[serde(default)]
    pub description: Option<String>,
    /// Версия политики (автоинкремент при изменении)
    pub version: u32,
    /// Тип политики
    #[serde(default)]
    pub policy_type: PolicyType,
    /// Цель применения
    #[serde(default)]
    pub target: PolicyTarget,
    /// Настройки политики (ключ → значение)
    #[serde(default)]
    pub settings: std::collections::HashMap<String, PolicyValue>,
    /// Включена ли политика
    pub enabled: bool,
    /// Принудительное применение (не унаследовано)
    pub enforced: bool,
    /// Порядок применения (чем меньше — тем выше приоритет)
    pub order: u32,
    /// Фильтрация по безопасности (только указанные SID могут применить)
    #[serde(default)]
    pub security_filtering: Vec<SidOrId>,
    /// WMI-фильтр (опционально, строка запроса)
    #[serde(default)]
    pub wmi_filter: Option<String>,
    /// Дата создания
    pub created_at: DateTime<Utc>,
    /// Дата последнего изменения
    pub updated_at: DateTime<Utc>,
    /// Список ID объектов, к которым привязана политика (OU, Domain)
    #[serde(default)]
    pub linked_to: Vec<Uuid>,
}

impl GroupPolicy {
    /// Создать новую политику с минимальными настройками
    pub fn new(name: impl Into<String>) -> Self {
        let name_str = name.into();
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name: name_str.clone(),
            display_name: Some(name_str),
            description: None,
            version: 1,
            policy_type: PolicyType::default(),
            target: PolicyTarget::default(),
            settings: std::collections::HashMap::new(),
            enabled: true,
            enforced: false,
            order: 0,
            security_filtering: vec![],
            wmi_filter: None,
            created_at: now,
            updated_at: now,
            linked_to: vec![],
        }
    }

    /// Увеличить версию и обновить временные метки
    pub fn increment_version(&mut self) {
        self.version += 1;
        self.updated_at = Utc::now();
    }

    /// Добавить связь с OU или Domain
    pub fn link_to(&mut self, id: Uuid) {
        if !self.linked_to.contains(&id) {
            self.linked_to.push(id);
        }
    }

    /// Удалить связь
    pub fn unlink(&mut self, id: &Uuid) {
        self.linked_to.retain(|linked_id| linked_id != id);
    }

    /// Установить настройку
    pub fn set_setting<K, V>(&mut self, key: K, value: V) -> Result<(), String>
    where
        K: Into<String>,
        V: Into<PolicyValue>,
    {
        self.settings.insert(key.into(), value.into());
        Ok(())
    }

    /// Получить значение настройки
    pub fn get_setting(&self, key: &str) -> Option<&PolicyValue> {
        self.settings.get(key)
    }

    /// Проверить, применима ли политика к пользователю/группе
    pub fn is_applicable_to(
        &self,
        principal_sid: &SecurityIdentifier,
        group_sids: &[SecurityIdentifier],
    ) -> bool {
        if !self.enabled {
            return false;
        }

        // Если есть фильтрация — проверяем
        if !self.security_filtering.is_empty() {
            let allowed = self.security_filtering.iter().any(|filter| match filter {
                SidOrId::Sid(sid) => sid == principal_sid || group_sids.contains(sid),
                SidOrId::Id(_) => false,
            });
            if !allowed {
                return false;
            }
        }

        // WMI фильтры пока не реализованы
        true
    }

    /// Проверить целостность политики
    pub fn validate(&self) -> Result<(), String> {
        // ✅ self.name: String → можно вызывать .trim()
        if self.name.trim().is_empty() {
            return Err("Policy name cannot be empty".to_string());
        }

        // ✅ display_name: Option<String> → безопасно проверяем через as_deref()
        if let Some(display_name) = &self.display_name {
            if display_name.trim().is_empty() {
                return Err("Display name cannot be empty".to_string());
            }
        }

        if self.version == 0 {
            return Err("Version must be at least 1".to_string());
        }

        if self.linked_to.is_empty() && !self.target.is_all() {
            return Err("Policy must be linked to an object or target 'All'".to_string());
        }
        Ok(())
    }

    /// Обновить временную метку
    pub fn touch(&mut self) {
        self.increment_version();
    }
}

// === Дефолты ===

impl Default for GroupPolicy {
    fn default() -> Self {
        Self::new("New GPO")
    }
}

// === Сравнение ===

impl PartialEq for GroupPolicy {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for GroupPolicy {}

// === Конструкторы ===

impl GroupPolicy {
    pub fn with_type(mut self, policy_type: PolicyType) -> Self {
        self.policy_type = policy_type;
        self
    }

    pub fn enforce(mut self) -> Self {
        self.enforced = true;
        self
    }

    pub fn disable(mut self) -> Self {
        self.enabled = false;
        self
    }

    pub fn order(mut self, order: u32) -> Self {
        self.order = order;
        self
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}