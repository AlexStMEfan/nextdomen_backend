// src/middleware.rs

use axum::{
    async_trait,
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::Arc;

use crate::directory_service::DirectoryService;
use crate::auth::{self, Claims};

/// Состояние приложения
pub type AppState = Arc<DirectoryService>;

/// Типизированный результат для обработки ошибок
#[derive(Debug)]
pub enum AuthError {
    NoToken,
    InvalidToken,
    DecodeError,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::NoToken => (StatusCode::UNAUTHORIZED, "Missing token"),
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid or expired token"),
            AuthError::DecodeError => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to decode token"),
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}

/// Извлечение `Claims` из заголовка Authorization
#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // 1. Получить заголовок Authorization
        let auth_header = parts.headers
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "));

        let token = auth_header.ok_or(AuthError::NoToken)?;

        // 2. Валидировать токен
        match auth::validate_token(token) {
            Ok(claims) => Ok(claims),
            Err(_) => Err(AuthError::InvalidToken),
        }
    }
}

/// Middleware: проверяет JWT и извлекает `Claims`
pub async fn auth_middleware(
    claims: Result<Claims, AuthError>,
) -> Result<impl IntoResponse, AuthError> {
    match claims {
        Ok(claims) => {
            // Можно добавить логирование или аудит
            Ok(Json(json!({
                "status": "authenticated",
                "user_id": claims.sub
            })))
        }
        Err(e) => Err(e),
    }
}

/// Утилита: проверка, является ли пользователь админом (пример)
pub async fn require_admin(
    claims: Claims,
    State(service): State<AppState>,
) -> Result<Claims, AuthError> {
    let user = service.get_user(uuid::Uuid::parse_str(&claims.sub).map_err(|_| AuthError::DecodeError)?).await
        .map_err(|_| AuthError::InvalidToken)?
        .ok_or(AuthError::InvalidToken)?;

    if !user.is_admin() {
        return Err(AuthError::InvalidToken); // или создать свой `Forbidden`
    }

    Ok(claims)
}