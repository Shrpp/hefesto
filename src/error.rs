use thiserror::Error;

/// Errors returned by hefesto operations.
///
/// All variants implement [`std::error::Error`] via [`thiserror`]. The
/// [`Display`](std::fmt::Display) messages are human-readable and safe to log.
#[derive(Debug, Error)]
pub enum HefestoError {
    /// AES-256-GCM encryption failed.
    #[error("encryption failed")]
    EncryptionFailed,

    /// AES-256-GCM decryption failed. Caused by a wrong key, wrong tenant,
    /// modified AAD, or tampered ciphertext.
    #[error("decryption failed — wrong key or tampered data")]
    DecryptionFailed,

    /// Argon2id key derivation failed, typically due to invalid parameters.
    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Ciphertext is not valid base64, or the version byte does not match.
    #[error("invalid payload — data may be corrupted")]
    InvalidPayload,

    /// Ciphertext is shorter than the minimum required length.
    #[error("payload too short — expected at least {expected} bytes, got {got}")]
    PayloadTooShort {
        /// Minimum number of bytes required.
        expected: usize,
        /// Actual number of bytes received.
        got: usize,
    },

    /// Decrypted bytes are not valid UTF-8. Should not occur with correctly
    /// encrypted UTF-8 plaintexts.
    #[error("invalid UTF-8 in decrypted data")]
    InvalidUtf8,

    /// Argon2id password hashing failed.
    #[error("password hashing failed: {0}")]
    PasswordHashFailed(String),

    /// A key argument is shorter than the 8-byte minimum.
    #[error("invalid key: {0}")]
    InvalidKey(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, HefestoError>;
