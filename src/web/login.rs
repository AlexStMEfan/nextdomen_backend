// src/web/login.rs

use axum::{
    extract::{State, Json},
    response::IntoResponse,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::directory_service::DirectoryService;
use crate::auth;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user_id: String,
    pub expires_in: usize,
}

pub async fn login_handler(
    State(service): State<Arc<DirectoryService>>,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse, LoginError> {
    let user = service.find_user_by_username(&payload.username).await
        .map_err(|_| LoginError::Internal)?
        .ok_or(LoginError::InvalidCredentials)?;

    if !user.password_hash.verify(&payload.password)
        .map_err(|_| LoginError::Internal)? {
        return Err(LoginError::InvalidCredentials);
    }

    let token = auth::generate_token(&user.id.to_string())
        .map_err(|_| LoginError::TokenGeneration)?;

    Ok((
        StatusCode::OK,
        Json(LoginResponse {
            token,
            user_id: user.id.to_string(),
            expires_in: 86400,
        }),
    ).into_response())
}

#[derive(Debug)]
pub enum LoginError {
    InvalidCredentials,
    Internal,
    TokenGeneration,
}

impl IntoResponse for LoginError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            LoginError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid username or password"),
            LoginError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
            LoginError::TokenGeneration => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate token"),
        };

        (status, format!("{{\"error\":\"{}\"}}", message)).into_response()
    }
}