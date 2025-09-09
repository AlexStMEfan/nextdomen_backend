// src/raddb.rs

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use bincode;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

// 🔁 Добавлено: RngCore для fill_bytes
use rand::{rngs::OsRng, RngCore};

#[allow(dead_code)]
#[derive(Debug)]
pub enum RadDbError {
    Io(std::io::Error),
    Serialization(String),
    Decryption(String),
    Encryption(String),
    KeyInvalid,
}

impl From<std::io::Error> for RadDbError {
    fn from(e: std::io::Error) -> Self {
        RadDbError::Io(e)
    }
}

impl std::fmt::Display for RadDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RadDbError::Io(e) => write!(f, "IO error: {}", e),
            RadDbError::Serialization(e) => write!(f, "Serialization error: {}", e),
            RadDbError::Decryption(e) => write!(f, "Decryption error: {}", e),
            RadDbError::Encryption(e) => write!(f, "Encryption error: {}", e),
            RadDbError::KeyInvalid => write!(f, "Invalid key length"),
        }
    }
}

impl std::error::Error for RadDbError {}

/// Ключ шифрования (32 байта = 256 бит)
pub type MasterKey = [u8; 32];

/// RadDB — зашифрованная embedded база
pub struct RadDB {
    path: PathBuf,
    cipher: Aes256Gcm,
    cache: RwLock<HashMap<String, Vec<u8>>>,
}

impl RadDB {
    /// Открыть базу по пути с мастер-ключом
    pub fn open<P: AsRef<Path>>(path: P, key: &MasterKey) -> Result<Self, RadDbError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let db = Self {
            path: path.as_ref().to_path_buf(),
            cipher,
            cache: RwLock::new(HashMap::new()),
        };
        db.load()?;
        Ok(db)
    }

    #[allow(dead_code)]
    /// Создать новый мастер-ключ (надо сохранить!)
    pub fn generate_key() -> MasterKey {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key); // ✅ Теперь работает
        key
    }

    /// Загрузить данные из файла
    fn load(&self) -> Result<(), RadDbError> {
        // Проверяем, существует ли файл
        if !self.path.exists() {
            return Ok(()); // Файл не существует → пустая база
        }

        let mut file = OpenOptions::new().read(true).open(&self.path)?;
        let mut encrypted = Vec::new();
        file.read_to_end(&mut encrypted)?;

        if encrypted.is_empty() {
            return Ok(());
        }

        if encrypted.len() < 12 {
            return Err(RadDbError::Decryption("File too short".to_string()));
        }

        let (nonce_bytes, ciphertext) = encrypted.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let payload = Payload {
            msg: ciphertext,
            aad: &[], // нет дополнительных данных
        };

        let plaintext = self
            .cipher
            .decrypt(nonce, payload)
            .map_err(|_| RadDbError::Decryption("AES-GCM decryption failed".to_string()))?;

        // ✅ Правильно: объявляем переменную `data` с типом
        let data: HashMap<String, Vec<u8>> = bincode::deserialize(&plaintext)
            .map_err(|e| RadDbError::Serialization(e.to_string()))?;

        let mut cache = self.cache.write().map_err(|_| RadDbError::Io(std::io::Error::new(std::io::ErrorKind::Other, "RwLock poisoned")))?;
        *cache = data;

        Ok(())
    }

    /// Сохранить данные на диск
    pub fn flush(&self) -> Result<(), RadDbError> {
        let cache = self.cache.read().map_err(|_| RadDbError::Io(std::io::Error::new(std::io::ErrorKind::Other, "RwLock poisoned")))?;
        let plaintext = bincode::serialize(&*cache)
            .map_err(|e| RadDbError::Serialization(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: &plaintext,
            aad: &[], // нет дополнительных данных
        };

        let ciphertext = self
            .cipher
            .encrypt(nonce, payload)
            .map_err(|_| RadDbError::Encryption("AES-GCM encryption failed".to_string()))?;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)?;

        file.write_all(&nonce_bytes)?;
        file.write_all(&ciphertext)?;
        file.sync_all()?;

        Ok(())
    }

    /// Получить значение по ключу
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let cache = self.cache.read().ok()?;
        cache.get(key).cloned()
    }

    /// Проверить наличие ключа
    #[allow(dead_code)]
    pub fn contains_key(&self, key: &str) -> bool {
        match self.cache.read() {
            Ok(cache) => cache.contains_key(key),
            Err(_) => false,
        }
    }

    /// Установить значение
    pub fn set(&self, key: String, value: Vec<u8>) -> Result<(), RadDbError> {
        let mut cache = self.cache.write().map_err(|_| RadDbError::Io(std::io::Error::new(std::io::ErrorKind::Other, "RwLock poisoned")))?;
        cache.insert(key, value);
        self.flush()?;
        Ok(())
    }

    /// Удалить ключ
    pub fn remove(&self, key: &str) -> bool {
        let mut cache = self.cache.write().unwrap();
        cache.remove(key).is_some()
    }

    #[allow(dead_code)]
    /// Очистить кэш (не сохраняет на диск)
    pub fn clear(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.clear();
    }
}

// Автоматическое сохранение при выходе
impl Drop for RadDB {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}