use thiserror::Error;

#[derive(Debug, Error)]
pub enum HefestoError {
    #[error("encryption failed")]
    EncryptionFailed,

    #[error("decryption failed — wrong key or tampered data")]
    DecryptionFailed,

    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("invalid payload — data may be corrupted")]
    InvalidPayload,

    #[error("payload too short — expected at least {expected} bytes, got {got}")]
    PayloadTooShort { expected: usize, got: usize },

    #[error("invalid UTF-8 in decrypted data")]
    InvalidUtf8,

    #[error("password hashing failed: {0}")]
    PasswordHashFailed(String),
}

pub type Result<T> = std::result::Result<T, HefestoError>;
