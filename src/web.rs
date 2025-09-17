// src/web.rs

use axum::{
    routing::{get, post, delete},
    Router,
    Json,
    extract::{Path, State},
    response::IntoResponse,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::directory_service::{DirectoryService, DirectoryError};

// === Тип состояния ===
pub type SharedService = Arc<DirectoryService>;

// === Запросы ===

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub surname: Option<String>,
}

impl CreateUserRequest {
    fn validate(&self) -> Result<(), DirectoryError> {
        if self.username.is_empty() || self.username.len() > 64 {
            return Err(DirectoryError::InvalidInput("Username must be 1-64 characters".to_string()));
        }
        if let Some(email) = &self.email {
            if !email.contains('@') {
                return Err(DirectoryError::InvalidInput("Invalid email format".to_string()));
            }
        }
        Ok(())
    }
}

#[derive(Deserialize, Default)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub surname: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    #[serde(default)]
    pub sam_account_name: Option<String>,
}

impl CreateGroupRequest {
    fn validate(&self) -> Result<(), DirectoryError> {
        if self.name.is_empty() {
            return Err(DirectoryError::InvalidInput("Group name cannot be empty".to_string()));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
pub struct CreateOuRequest {
    pub name: String,
    #[serde(default)]
    pub parent: Option<String>,
}

impl CreateOuRequest {
    fn validate(&self) -> Result<(), DirectoryError> {
        if self.name.is_empty() {
            return Err(DirectoryError::InvalidInput("OU name cannot be empty".to_string()));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
pub struct CreateGpoRequest {
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub linked_to: Vec<uuid::Uuid>,
    #[serde(default)]
    pub enforced: bool,
    #[serde(default)]
    pub enabled: bool,
}

impl CreateGpoRequest {
    fn validate(&self) -> Result<(), DirectoryError> {
        if self.name.is_empty() {
            return Err(DirectoryError::InvalidInput("GPO name cannot be empty".to_string()));
        }
        if self.linked_to.is_empty() {
            return Err(DirectoryError::InvalidInput("GPO must be linked to at least one object".to_string()));
        }
        Ok(())
    }
}

// === Ответы ===

#[derive(Serialize)]
pub struct UserResponse {
    pub id: uuid::Uuid,
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub surname: Option<String>,
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub last_login: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<crate::models::User> for UserResponse {
    fn from(user: crate::models::User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            email: user.email,
            display_name: user.display_name,
            given_name: user.given_name,
            surname: user.surname,
            enabled: user.enabled,
            created_at: user.created_at,
            updated_at: user.updated_at,
            last_login: user.last_login,
        }
    }
}

#[derive(Serialize)]
pub struct GroupResponse {
    pub id: uuid::Uuid,
    pub name: String,
    pub sam_account_name: String,
    pub members_count: usize,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<crate::models::Group> for GroupResponse {
    fn from(group: crate::models::Group) -> Self {
        Self {
            id: group.id,
            name: group.name,
            sam_account_name: group.sam_account_name,
            members_count: group.members.len(),
            created_at: group.created_at,
        }
    }
}

#[derive(Serialize)]
pub struct OuResponse {
    pub id: uuid::Uuid,
    pub name: String,
    pub dn: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<crate::models::OrganizationalUnit> for OuResponse {
    fn from(ou: crate::models::OrganizationalUnit) -> Self {
        Self {
            id: ou.id,
            name: ou.name,
            dn: ou.dn,
            created_at: ou.created_at,
            updated_at: ou.updated_at,
        }
    }
}

#[derive(Serialize)]
pub struct GpoResponse {
    pub id: uuid::Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub linked_to: Vec<uuid::Uuid>,
    pub enforced: bool,
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<crate::models::policy::GroupPolicy> for GpoResponse {
    fn from(gpo: crate::models::policy::GroupPolicy) -> Self {
        Self {
            id: gpo.id,
            name: gpo.name,
            display_name: gpo.display_name,
            description: gpo.description,
            linked_to: gpo.linked_to,
            enforced: gpo.enforced,
            enabled: gpo.enabled,
            created_at: gpo.created_at,
            updated_at: gpo.updated_at,
        }
    }
}

// === Конвертация ошибок ===

impl IntoResponse for DirectoryError {
    fn into_response(self) -> axum::response::Response {
        let (status, body) = match &self {
            DirectoryError::NotFound(msg) => (
                StatusCode::NOT_FOUND,
                json!({ "error": msg }),
            ),
            DirectoryError::AlreadyExists(msg) => (
                StatusCode::CONFLICT,
                json!({ "error": msg }),
            ),
            DirectoryError::InvalidInput(msg) | DirectoryError::Serialization(msg) => (
                StatusCode::BAD_REQUEST,
                json!({ "error": msg }),
            ),
            DirectoryError::DbError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "error": "Database error" }),
            ),
        };
        (status, Json(body)).into_response()
    }
}

// === Обработчики: Users ===

async fn list_users(
    State(service): State<SharedService>,
) -> Result<Json<Vec<UserResponse>>, DirectoryError> {
    let users = service.get_all_users().await?;
    Ok(Json(users.into_iter().map(UserResponse::from).collect()))
}

async fn get_user(
    Path(username): Path<String>,
    State(service): State<SharedService>,
) -> Result<Json<UserResponse>, DirectoryError> {
    let user = service.find_user_by_username(&username)
        .await?
        .ok_or_else(|| DirectoryError::NotFound(format!("User not found: {}", username)))?;
    Ok(Json(UserResponse::from(user)))
}

async fn create_user(
    State(service): State<SharedService>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, DirectoryError> {
    payload.validate()?;
    
    use crate::models::{SecurityIdentifier, PasswordHash, PasswordAlgorithm};

    let user = crate::models::User {
        id: uuid::Uuid::new_v4(),
        sid: SecurityIdentifier::new_nt_authority(1001),
        username: payload.username.clone(),
        user_principal_name: format!("{}@corp.acme.com", payload.username),
        email: payload.email,
        display_name: payload.display_name,
        given_name: payload.given_name,
        surname: payload.surname,
        password_hash: PasswordHash {
            hash: "default_hash".to_string(),
            algorithm: PasswordAlgorithm::Bcrypt,
            salt: vec![],
        },
        password_expires: None,
        last_password_change: chrono::Utc::now(),
        lockout_until: None,
        failed_logins: 0,
        enabled: true,
        mfa_enabled: false,
        mfa_methods: vec![],
        domains: vec![],
        groups: vec![],
        organizational_unit: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        last_login: None,
        profile_path: None,
        script_path: None,
        meta: std::collections::HashMap::new(),
        primary_group_id: Some(513),
    };

    service.create_user(&user).await?;
    Ok((StatusCode::CREATED, Json(UserResponse::from(user))))
}

async fn update_user(
    Path(username): Path<String>,
    State(service): State<SharedService>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<impl IntoResponse, DirectoryError> {
    let mut user = service.find_user_by_username(&username)
        .await?
        .ok_or_else(|| DirectoryError::NotFound(format!("User not found: {}", username)))?;

    if let Some(email) = &payload.email {
        if let Some(existing) = service.find_user_by_email(email).await? {
            if existing.id != user.id {
                return Err(DirectoryError::AlreadyExists("Email already in use".to_string()));
            }
        }
        user.email = Some(email.clone());
    }

    if let Some(display_name) = &payload.display_name {
        user.display_name = Some(display_name.clone());
    }

    if let Some(given_name) = &payload.given_name {
        user.given_name = Some(given_name.clone());
    }

    if let Some(surname) = &payload.surname {
        user.surname = Some(surname.clone());
    }

    if let Some(enabled) = payload.enabled {
        user.enabled = enabled;
    }

    user.updated_at = chrono::Utc::now();
    service.update_user(&user).await?;

    Ok(Json(UserResponse::from(user)))
}

async fn delete_user(
    Path(username): Path<String>,
    State(service): State<SharedService>,
) -> Result<impl IntoResponse, DirectoryError> {
    let user = service.find_user_by_username(&username)
        .await?
        .ok_or_else(|| DirectoryError::NotFound(format!("User not found: {}", username)))?;

    service.delete_user(user.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// === Обработчики: Groups ===

async fn list_groups(
    State(service): State<SharedService>,
) -> Result<Json<Vec<GroupResponse>>, DirectoryError> {
    let groups = service.get_all_groups().await?;
    Ok(Json(groups.into_iter().map(GroupResponse::from).collect()))
}

async fn create_group(
    State(service): State<SharedService>,
    Json(payload): Json<CreateGroupRequest>,
) -> Result<impl IntoResponse, DirectoryError> {
    payload.validate()?;

    use crate::models::{GroupTypeFlags, GroupScope};

    let sam = payload.sam_account_name.unwrap_or_else(|| payload.name.to_uppercase());

    let group = crate::models::Group::new(
        payload.name,
        sam,
        uuid::Uuid::nil(),
        GroupTypeFlags::SECURITY,
        GroupScope::Global,
    );

    service.create_group(&group).await?;
    Ok((StatusCode::CREATED, Json(GroupResponse::from(group))))
}

async fn delete_group(
    Path(sam): Path<String>,
    State(service): State<SharedService>,
) -> Result<impl IntoResponse, DirectoryError> {
    let group = service.find_group_by_sam_account_name(&sam)
        .await?
        .ok_or_else(|| DirectoryError::NotFound(format!("Group not found: {}", sam)))?;

    service.delete_group(group.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// === Обработчики: OUs ===

async fn list_ous(
    State(service): State<SharedService>,
) -> Result<Json<Vec<OuResponse>>, DirectoryError> {
    let ous = service.get_all_ous().await?;
    Ok(Json(ous.into_iter().map(OuResponse::from).collect()))
}

async fn create_ou(
    State(service): State<SharedService>,
    Json(payload): Json<CreateOuRequest>,
) -> Result<impl IntoResponse, DirectoryError> {
    payload.validate()?;

    let parent_dn = payload.parent.as_deref();
    let dn = crate::directory_service::DirectoryService::generate_ou_dn(&payload.name, parent_dn);

    let ou = crate::models::OrganizationalUnit::new(payload.name, dn, None);
    service.create_ou(&ou).await?;

    Ok((StatusCode::CREATED, Json(OuResponse::from(ou))))
}

// === Обработчики: GPO ===

async fn create_gpo(
    State(service): State<SharedService>,
    Json(payload): Json<CreateGpoRequest>,
) -> Result<impl IntoResponse, DirectoryError> {
    payload.validate()?;

    use crate::models::policy::{PolicyType, PolicyTarget};

    let gpo = crate::models::policy::GroupPolicy {
        id: uuid::Uuid::new_v4(),
        name: payload.name,
        display_name: payload.display_name,
        description: payload.description,
        linked_to: payload.linked_to,
        enforced: payload.enforced,
        security_filtering: vec![],
        order: 0,
        version: 1,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        enabled: payload.enabled,
        policy_type: PolicyType::Custom("Custom".to_string()),
        target: PolicyTarget::All,
        settings: std::collections::HashMap::new(),
        wmi_filter: None,
    };

    service.create_gpo(&gpo).await?;
    Ok((StatusCode::CREATED, Json(GpoResponse::from(gpo))))
}

// === Health Check ===

async fn health() -> impl IntoResponse {
    Json(json!({ "status": "OK", "timestamp": chrono::Utc::now() }))
}

// === Запуск сервера ===

pub async fn run_web_server(service: Arc<DirectoryService>, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cors = tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any);

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/users", get(list_users).post(create_user))
        .route("/api/users/:username", get(get_user).put(update_user).delete(delete_user))
        .route("/api/groups", get(list_groups).post(create_group))
        .route("/api/groups/:sam", delete(delete_group))
        .route("/api/ous", get(list_ous).post(create_ou))
        .route("/api/gpos", post(create_gpo))
        .with_state(service)
        .layer(cors)
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("🌐 REST API запущен на http://{}", addr);

    axum::serve(listener, app).await?;
    Ok(())
}