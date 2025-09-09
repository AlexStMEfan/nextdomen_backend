// src/models/password.rs

use serde::{Deserialize, Serialize};
use std::fmt;

/// Алгоритм хеширования пароля
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum PasswordAlgorithm {
    Bcrypt,
    Argon2,
    Pbkdf2,
}

/// Хеш пароля с солью и алгоритмом
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PasswordHash {
    pub hash: String,           // строка вроде "$2b$12$..."
    pub algorithm: PasswordAlgorithm,
    pub salt: Vec<u8>,          // может быть пустым, если алгоритм включает соль в хеш (как bcrypt)
}

impl PasswordHash {
    /// Создать хеш с помощью bcrypt
    pub fn new_bcrypt(password: &str) -> Result<Self, PasswordError> {
        let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST)
            .map_err(|_| PasswordError::HashFailed)?;
        Ok(Self {
            hash,
            algorithm: PasswordAlgorithm::Bcrypt,
            salt: vec![], // bcrypt включает соль в сам хеш
        })
    }

    /// Проверить пароль
    pub fn verify(&self, password: &str) -> Result<bool, PasswordError> {
        match self.algorithm {
            PasswordAlgorithm::Bcrypt => {
                let valid = bcrypt::verify(password, &self.hash)
                    .map_err(|_| PasswordError::VerificationFailed)?;
                Ok(valid)
            }
            _ => Err(PasswordError::NotImplemented),
        }
    }
}

impl fmt::Display for PasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hash)
    }
}

#[derive(Debug)]
pub enum PasswordError {
    HashFailed,
    VerificationFailed,
    NotImplemented,
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordError::HashFailed => write!(f, "Failed to hash password"),
            PasswordError::VerificationFailed => write!(f, "Failed to verify password"),
            PasswordError::NotImplemented => write!(f, "Algorithm not implemented"),
        }
    }
}

impl std::error::Error for PasswordError {}