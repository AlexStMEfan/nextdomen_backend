// src/auth.rs

use jsonwebtoken::{encode, decode, Algorithm, Header, Validation, EncodingKey, DecodingKey};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;

use dotenvy::dotenv;

// Для RSA
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs8::EncodePrivateKey; // for .to_pkcs8_der()
use rsa::RsaPrivateKey;

static CONFIG: Lazy<Result<AuthConfig, AuthError>> = Lazy::new(|| {
    dotenv().ok();
    AuthConfig::from_env()
});

#[derive(Debug, Clone)]
pub enum AuthError {
    EnvVarNotFound(String),
    KeyReadFailed(String),
    InvalidKeyFormat(String),
}

// Реализация для jsonwebtoken::errors::Error
impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        match e.kind() {
            jsonwebtoken::errors::ErrorKind::InvalidKeyFormat => {
                AuthError::InvalidKeyFormat("Invalid key format".into())
            }
            jsonwebtoken::errors::ErrorKind::InvalidAlgorithmName => {
                AuthError::InvalidKeyFormat("Invalid algorithm name".into())
            }
            _ => AuthError::InvalidKeyFormat(e.to_string()),
        }
    }
}

// Реализация для std::env::VarError
impl From<std::env::VarError> for AuthError {
    fn from(e: std::env::VarError) -> Self {
        AuthError::EnvVarNotFound(e.to_string())
    }
}

// Реализация для rsa::pkcs8::Error
impl From<rsa::pkcs8::Error> for AuthError {
    fn from(e: rsa::pkcs8::Error) -> Self {
        AuthError::InvalidKeyFormat(e.to_string())
    }
}

// Реализация для String → AuthError
impl From<String> for AuthError {
    fn from(s: String) -> Self {
        AuthError::InvalidKeyFormat(s)
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::EnvVarNotFound(var) => write!(f, "Environment variable not set: {}", var),
            AuthError::KeyReadFailed(path) => write!(f, "Failed to read key file: {}", path),
            AuthError::InvalidKeyFormat(msg) => write!(f, "Invalid key format: {}", msg),
        }
    }
}

impl std::error::Error for AuthError {}

struct AuthConfig {
    private_key_pem: Vec<u8>,
    public_key_pem: Vec<u8>,
}

impl AuthConfig {
    fn from_env() -> Result<Self, AuthError> {
        let private_key_path = env::var("JWT_PRIVATE_KEY_PATH")?;
        let public_key_path = env::var("JWT_PUBLIC_KEY_PATH")?;

        let private_key_pem = fs::read(&private_key_path).map_err(|_| {
            AuthError::KeyReadFailed(private_key_path.clone())
        })?;
        let public_key_pem = fs::read(&public_key_path).map_err(|_| {
            AuthError::KeyReadFailed(public_key_path.clone())
        })?;

        Ok(Self {
            private_key_pem,
            public_key_pem,
        })
    }
}

// === Claims ===

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub exp: usize,
    pub iat: usize,
}

// === Функции ===

use chrono;

pub fn generate_token(user_id: &str) -> Result<String, AuthError> {
    let config = CONFIG.as_ref().map_err(|e| e.clone())?;

    let private_key = RsaPrivateKey::from_pkcs8_pem(
        &String::from_utf8(config.private_key_pem.clone())
            .map_err(|_| AuthError::InvalidKeyFormat("Private key is not valid UTF-8".into()))?
    )?;

    let der = private_key.to_pkcs8_der()?;
    let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());

    let header = Header {
        alg: Algorithm::RS256,
        ..Header::default()
    };

    let now = chrono::Utc::now().timestamp() as usize;
    let claims = Claims {
        sub: user_id.to_owned(),
        exp: now + 24 * 3600,
        iat: now,
    };

    encode(&header, &claims, &encoding_key).map_err(Into::into)
}

pub fn validate_token(token: &str) -> Result<Claims, AuthError> {
    let config = CONFIG.as_ref().map_err(|e| e.clone())?;

    let decoding_key = DecodingKey::from_rsa_pem(&config.public_key_pem)?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;

    let data = decode::<Claims>(token, &decoding_key, &validation)?;
    Ok(data.claims)
}