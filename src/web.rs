// src/web.rs

use axum::{
    routing::{get},
    Router, Json, extract::{Path, State},
    response::IntoResponse,
    http::StatusCode,
};
use crate::directory_service::DirectoryService;
use crate::models::{User, PasswordHash};
use std::sync::Arc;
use uuid::Uuid;
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub surname: Option<String>,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub surname: Option<String>,
    pub enabled: bool,
    pub created_at: chrono::DateTime<Utc>,
    pub last_login: Option<chrono::DateTime<Utc>>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            email: user.email,
            display_name: user.display_name,
            given_name: user.given_name,
            surname: user.surname,
            enabled: user.enabled,
            created_at: user.created_at,
            last_login: user.last_login,
        }
    }
}

async fn list_users(
    State(service): State<Arc<DirectoryService>>,
) -> impl IntoResponse {
    let users: Vec<User> = service.get_all_users().await.unwrap_or_default();
    let responses: Vec<UserResponse> = users.into_iter().map(UserResponse::from).collect();
    Json(responses)
}

async fn get_user(
    Path(username): Path<String>,
    State(service): State<Arc<DirectoryService>>,
) -> impl IntoResponse {
    match service.find_user_by_username(&username).await {
        Ok(Some(user)) => (StatusCode::OK, Json(UserResponse::from(user))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "User not found",
                "username": username
            }))
        ).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Internal error"
            }))
        ).into_response(),
    }
}

async fn create_user(
    State(service): State<Arc<DirectoryService>>,
    Json(payload): Json<CreateUserRequest>,
) -> impl IntoResponse {
    if payload.username.is_empty() || payload.username.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid username"
            }))
        ).into_response();
    }

    if payload.username.chars().any(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-') {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Username contains invalid characters"
            }))
        ).into_response();
    }

    if let Some(email) = &payload.email {
        if !email.contains('@') || email.len() > 254 {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid email format"
                }))
            ).into_response();
        }
    }

    match service.find_user_by_username(&payload.username).await {
        Ok(Some(_)) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "User with this username already exists"
                }))
            ).into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Internal error"
                }))
            ).into_response();
        }
        Ok(None) => {}
    }

    if let Some(email) = &payload.email {
        match service.find_user_by_email(email).await {
            Ok(Some(_)) => {
                return (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({
                        "error": "User with this email already exists"
                    }))
                ).into_response();
            }
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "Internal error"
                    }))
                ).into_response();
            }
            Ok(None) => {}
        }
    }

    use crate::models::{SecurityIdentifier, PasswordAlgorithm};

    let user = User {
        id: Uuid::new_v4(),
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
        last_password_change: Utc::now(),
        lockout_until: None,
        failed_logins: 0,
        enabled: true,
        mfa_enabled: false,
        mfa_methods: vec![],
        domains: vec![],
        groups: vec![],
        organizational_unit: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login: None,
        profile_path: None,
        script_path: None,
        meta: std::collections::HashMap::new(),
        primary_group_id: Some(513),
    };

    if let Err(_) = service.create_user(&user).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to create user"
            }))
        ).into_response();
    }

    (StatusCode::CREATED, Json(UserResponse::from(user))).into_response()
}

pub async fn run_web_server(service: Arc<DirectoryService>, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let service = service.clone();

    let cors = tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any);

    let app = Router::new()
        .route("/api/users", get(list_users).post(create_user))
        .route("/api/users/:username", get(get_user))
        .with_state(service)
        .layer(cors)
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("🌐 Web API запущен на http://{}", addr);

    axum::serve(listener, app).await?;
    Ok(())
}