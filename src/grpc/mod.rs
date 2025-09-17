// src/grpc/mod.rs

pub mod gen; // Сгенерированный код

use tonic::{transport::Server, Request, Response, Status};
use std::sync::Arc;
use jsonwebtoken::{encode, decode, EncodingKey, DecodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::directory_service::DirectoryService;
use crate::models::User;

// === JWT Config ===

static SECRET: &[u8] = b"your-super-secret-jwt-key-for-nextdomen"; // Замени на env var!

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // user_id
    exp: usize,
}

// === Сервисы ===

pub mod user_api {
    tonic::include_proto!("user_api"); // Путь из package user_api;
}

pub mod auth_api {
    tonic::include_proto!("auth_api");
}

// === User API ===

#[derive(Clone)]
pub struct UserApiService {
    service: Arc<DirectoryService>,
}

#[tonic::async_trait]
impl user_api::user_api_server::UserApi for UserApiService {
    async fn get_user(
        &self,
        request: Request<user_api::GetUserRequest>,
    ) -> Result<Response<user_api::GetUserResponse>, Status> {
        let username = &request.into_inner().username;
        let user = self.service.find_user_by_username(username)
            .await
            .map_err(|_| Status::internal("DB error"))?
            .ok_or(Status::not_found("User not found"))?;

        Ok(Response::new(user_api::GetUserResponse {
            id: user.id.to_string(),
            username: user.username,
            email: user.email.unwrap_or_default(),
            display_name: user.display_name.unwrap_or_default(),
            created_at: user.created_at.timestamp(),
        }))
    }

    async fn list_users(
        &self,
        _request: Request<user_api::ListUsersRequest>,
    ) -> Result<Response<user_api::ListUsersResponse>, Status> {
        let users = self.service.get_all_users().await
            .map_err(|_| Status::internal("DB error"))?;

        let responses: Vec<_> = users.into_iter().map(|u| user_api::GetUserResponse {
            id: u.id.to_string(),
            username: u.username,
            email: u.email.unwrap_or_default(),
            display_name: u.display_name.unwrap_or_default(),
            created_at: u.created_at.timestamp(),
        }).collect();

        Ok(Response::new(user_api::ListUsersResponse { users: responses }))
    }

    async fn create_user(
        &self,
        request: Request<user_api::CreateUserRequest>,
    ) -> Result<Response<user_api::CreateUserResponse>, Status> {
        let req = request.into_inner();
        use crate::models::{SecurityIdentifier, PasswordHash, PasswordAlgorithm};

        let user = User {
            id: uuid::Uuid::new_v4(),
            sid: SecurityIdentifier::new_nt_authority(1001),
            username: req.username.clone(),
            user_principal_name: format!("{}@corp.acme.com", req.username),
            email: req.email.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            display_name: req.display_name.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            given_name: None,
            surname: None,
            password_hash: PasswordHash {
                hash: "default".to_string(),
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

        self.service.create_user(&user).await
            .map_err(|_| Status::internal("Failed to create user"))?;

        Ok(Response::new(user_api::CreateUserResponse {
            id: user.id.to_string(),
        }))
    }
}

// === Auth API ===

#[derive(Clone)]
pub struct AuthService {
    service: Arc<DirectoryService>,
}

#[tonic::async_trait]
impl auth_api::auth_api_server::AuthService for AuthService {
    async fn login(
        &self,
        request: Request<auth_api::LoginRequest>,
    ) -> Result<Response<auth_api::LoginResponse>, Status> {
        let req = request.into_inner();
        let user = self.service.find_user_by_username(&req.username)
            .await
            .map_err(|_| Status::internal("DB error"))?
            .ok_or(Status::unauthenticated("Invalid credentials"))?;

        // В реальности: проверь пароль
        // Здесь: заглушка
        if req.password != "password" {
            return Err(Status::unauthenticated("Invalid credentials"));
        }

        let expiration = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::hours(24))
            .expect("Valid timestamp")
            .timestamp() as usize;

        let claims = Claims {
            sub: user.id.to_string(),
            exp: expiration,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(SECRET),
        ).map_err(|_| Status::internal("JWT encode error"))?;

        Ok(Response::new(auth_api::LoginResponse {
            token,
            expires_at: expiration as i64,
            user_id: user.id.to_string(),
        }))
    }

    async fn validate_token(
        &self,
        request: Request<auth_api::ValidateTokenRequest>,
    ) -> Result<Response<auth_api::ValidateTokenResponse>, Status> {
        let token = &request.into_inner().token;

        match decode::<Claims>(token, &DecodingKey::from_secret(SECRET), &Validation::default()) {
            Ok(_) => {
                // В реальности: получи user_id из токена
                Ok(Response::new(auth_api::ValidateTokenResponse {
                    valid: true,
                    user_id: "unknown".to_string(), // Добавь из claims.sub
                }))
            }
            Err(_) => Ok(Response::new(auth_api::ValidateTokenResponse {
                valid: false,
                user_id: "".to_string(),
            })),
        }
    }
}

// === Запуск сервера ===

pub async fn run_grpc_server(service: Arc<DirectoryService>, addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = addr.parse()?;
    let user_api = user_api::user_api_server::UserApiServer::new(UserApiService { service: service.clone() });
    let auth_api = auth_api::auth_api_server::AuthServiceServer::new(AuthService { service });

    Server::builder()
        .add_service(user_api)
        .add_service(auth_api)
        .serve(addr)
        .await?;

    Ok(())
}