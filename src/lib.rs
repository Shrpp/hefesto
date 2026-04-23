//! # hefesto
//!
//! Double envelope encryption for multi-tenant applications.
//!
//! Each value is encrypted with two independent keys — a per-tenant key and a
//! global master key — so a breach of either key alone does not expose
//! plaintext. The outer layer also binds the ciphertext to the tenant via AEAD
//! additional data, preventing cross-tenant replay.
//!
//! ## Security model
//!
//! ```text
//! plaintext
//!   └─▶ AES-256-GCM(key = Argon2id(tenant_key, salt₁))          ← inner layer
//!         └─▶ AES-256-GCM(key = Argon2id(master_key, salt₂),
//!                          aad = tenant_key)                      ← outer layer
//!               └─▶ base64(version ‖ salt₁ ‖ salt₂ ‖ ciphertext)
//! ```
//!
//! | Property | Mechanism |
//! |---|---|
//! | Confidentiality | AES-256-GCM (two layers) |
//! | Key hardening | Argon2id (64 MiB, 3 iterations) |
//! | Non-determinism | 96-bit random nonce per encryption |
//! | Tenant isolation | `tenant_key` used as AAD on outer layer |
//! | Memory safety | `zeroize` zeroes key material on drop |
//!
//! ## Quick start
//!
//! ```rust
//! use hefesto::{encrypt, decrypt, hash_password, verify_password, hash_for_lookup};
//!
//! let tenant_key = "per_tenant_secret_key";
//! let master_key = "global_master_key_32";
//!
//! // Encrypt and decrypt a sensitive value
//! let ciphertext = encrypt("user@example.com", tenant_key, master_key).unwrap();
//! let plaintext  = decrypt(&ciphertext, tenant_key, master_key).unwrap();
//! assert_eq!(plaintext, "user@example.com");
//!
//! // Hash a password for storage (Argon2id PHC string)
//! let hash = hash_password("s3cr3t").unwrap();
//! assert!(verify_password("s3cr3t", &hash));
//!
//! // Deterministic lookup token — same value + same tenant_key → same hash
//! let token = hash_for_lookup("user@example.com", tenant_key);
//! assert_eq!(token, hash_for_lookup("user@example.com", tenant_key));
//! ```
//!
//! ## Minimum key length
//!
//! Both `tenant_key` and `master_key` must be at least **8 bytes**. Shorter
//! keys are rejected with [`HefestoError::InvalidKey`].
//!
//! ## Feature flags
//!
//! This crate has no optional features. All primitives are always compiled.

#![warn(missing_docs)]

mod cipher;
mod envelope;
mod error;
mod kdf;
mod lookup;
mod password;

pub use error::HefestoError;
use error::Result;

const MIN_KEY_LEN: usize = 8;

fn validate_key(key: &str, name: &str) -> Result<()> {
    if key.len() < MIN_KEY_LEN {
        return Err(HefestoError::InvalidKey(format!(
            "{name} must be at least {MIN_KEY_LEN} bytes, got {}",
            key.len()
        )));
    }
    Ok(())
}

/// Encrypts `value` using double envelope encryption.
///
/// Applies two independent AES-256-GCM layers — first with a key derived from
/// `tenant_key`, then with a key derived from `master_key`. The outer layer
/// uses `tenant_key` as additional authenticated data (AAD), binding the
/// ciphertext to this tenant.
///
/// Each call produces a different ciphertext because both layers use a fresh
/// random nonce and salt.
///
/// # Arguments
///
/// * `value`      — plaintext to encrypt (any UTF-8 string, including empty)
/// * `tenant_key` — per-tenant secret; minimum 8 bytes
/// * `master_key` — global master secret; minimum 8 bytes
///
/// # Returns
///
/// Base64-encoded payload: `version(1) ‖ salt₁(16) ‖ salt₂(16) ‖ ciphertext`.
///
/// # Errors
///
/// * [`HefestoError::InvalidKey`]       — either key is shorter than 8 bytes
/// * [`HefestoError::KeyDerivationFailed`] — Argon2id parameterisation failed
/// * [`HefestoError::EncryptionFailed`] — AES-GCM encryption error
///
/// # Examples
///
/// ```rust
/// let ct = hefesto::encrypt("secret", "tenant_secret_key", "master_secret_k").unwrap();
/// assert!(!ct.is_empty());
///
/// // Non-deterministic: two calls with the same inputs produce different ciphertexts
/// let ct2 = hefesto::encrypt("secret", "tenant_secret_key", "master_secret_k").unwrap();
/// assert_ne!(ct, ct2);
/// ```
pub fn encrypt(value: &str, tenant_key: &str, master_key: &str) -> Result<String> {
    validate_key(tenant_key, "tenant_key")?;
    validate_key(master_key, "master_key")?;
    envelope::envelope_encrypt(value, tenant_key, master_key)
}

/// Decrypts a ciphertext produced by [`encrypt`].
///
/// Reverses the double envelope: first strips the outer AES-256-GCM layer
/// (keyed from `master_key`, with `tenant_key` as AAD), then strips the inner
/// layer (keyed from `tenant_key`).
///
/// # Arguments
///
/// * `ciphertext` — base64-encoded payload from [`encrypt`]
/// * `tenant_key` — per-tenant secret used during encryption
/// * `master_key` — global master secret used during encryption
///
/// # Errors
///
/// * [`HefestoError::InvalidKey`]       — either key is shorter than 8 bytes
/// * [`HefestoError::InvalidPayload`]   — not valid base64 or version byte mismatch
/// * [`HefestoError::PayloadTooShort`]  — payload is too short to be valid
/// * [`HefestoError::DecryptionFailed`] — wrong key, wrong tenant, or tampered data
/// * [`HefestoError::InvalidUtf8`]      — decrypted bytes are not valid UTF-8
///
/// # Examples
///
/// ```rust
/// let ct = hefesto::encrypt("hello", "tenant_secret_key", "master_secret_k").unwrap();
/// let pt = hefesto::decrypt(&ct, "tenant_secret_key", "master_secret_k").unwrap();
/// assert_eq!(pt, "hello");
/// ```
///
/// Wrong keys are rejected:
///
/// ```rust
/// let ct = hefesto::encrypt("hello", "tenant_secret_key", "master_secret_k").unwrap();
/// assert!(hefesto::decrypt(&ct, "wrong_tenant_key_", "master_secret_k").is_err());
/// assert!(hefesto::decrypt(&ct, "tenant_secret_key", "wrong_master_key_").is_err());
/// ```
pub fn decrypt(ciphertext: &str, tenant_key: &str, master_key: &str) -> Result<String> {
    validate_key(tenant_key, "tenant_key")?;
    validate_key(master_key, "master_key")?;
    envelope::envelope_decrypt(ciphertext, tenant_key, master_key)
}

/// Hashes a password using Argon2id and returns a PHC-format string.
///
/// Uses `Argon2::default()` parameters (Argon2id, version 0x13) with a
/// randomly generated salt. The output is a self-describing PHC string that
/// can be stored directly and passed to [`verify_password`].
///
/// Each call produces a different hash because the salt is random.
///
/// # Errors
///
/// * [`HefestoError::PasswordHashFailed`] — Argon2 hashing failed
///
/// # Examples
///
/// ```rust
/// let hash = hefesto::hash_password("my_password").unwrap();
/// assert!(hash.starts_with("$argon2id$"));
/// assert!(hefesto::verify_password("my_password", &hash));
/// ```
pub fn hash_password(password: &str) -> Result<String> {
    password::hash_password(password)
}

/// Verifies a password against an Argon2id PHC hash produced by [`hash_password`].
///
/// Returns `true` when the password matches the hash, `false` for any mismatch
/// or if `hash` is not a valid PHC string.
///
/// # Examples
///
/// ```rust
/// let hash = hefesto::hash_password("correct").unwrap();
/// assert!( hefesto::verify_password("correct", &hash));
/// assert!(!hefesto::verify_password("wrong",   &hash));
/// assert!(!hefesto::verify_password("correct", "not_a_valid_hash"));
/// ```
pub fn verify_password(password: &str, hash: &str) -> bool {
    password::verify_password(password, hash)
}

/// Computes a deterministic, tenant-scoped lookup token for a plaintext value.
///
/// Uses HMAC-SHA256 keyed with `tenant_key`. The output is a lowercase hex
/// string (64 characters). Because the same `tenant_key` always produces the
/// same token for the same `value`, this can be used to build a searchable
/// index over encrypted data (e.g., look up a user by email without decrypting
/// every row).
///
/// Two tenants with the same plaintext value produce different tokens, so
/// cross-tenant correlation is not possible from tokens alone.
///
/// # Arguments
///
/// * `value`      — plaintext to hash (e.g., an email address)
/// * `tenant_key` — per-tenant secret that scopes the token
///
/// # Returns
///
/// 64-character lowercase hex string (256-bit HMAC-SHA256 output).
///
/// # Examples
///
/// ```rust
/// let token = hefesto::hash_for_lookup("user@example.com", "tenant_secret_key");
///
/// // Deterministic: same inputs → same token
/// assert_eq!(token, hefesto::hash_for_lookup("user@example.com", "tenant_secret_key"));
///
/// // Tenant-scoped: different tenant → different token
/// assert_ne!(token, hefesto::hash_for_lookup("user@example.com", "other_tenant_key_"));
/// ```
pub fn hash_for_lookup(value: &str, tenant_key: &str) -> String {
    lookup::hash_for_lookup(value, tenant_key)
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    const TK: &str = "tenant_key_test";
    const MK: &str = "master_key_test";

    #[test]
    fn full_roundtrip() {
        let ct = encrypt("sensitive_data", TK, MK).unwrap();
        assert_eq!(decrypt(&ct, TK, MK).unwrap(), "sensitive_data");
    }

    #[test]
    fn password_roundtrip() {
        let hash = hash_password("password123").unwrap();
        assert!(verify_password("password123", &hash));
        assert!(!verify_password("wrong", &hash));
    }

    #[test]
    fn lookup_roundtrip() {
        let email = "user@example.com";
        let tenant_key = "tenant_secret";
        let lookup = hash_for_lookup(email, tenant_key);
        assert_eq!(lookup, hash_for_lookup(email, tenant_key));
    }

    #[test]
    fn encrypt_is_non_deterministic() {
        let ct1 = encrypt("data", TK, MK).unwrap();
        let ct2 = encrypt("data", TK, MK).unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn lookup_is_deterministic() {
        let h1 = hash_for_lookup("email", "key");
        let h2 = hash_for_lookup("email", "key");
        assert_eq!(h1, h2);
    }

    #[test]
    fn tenant_isolation_in_lookup() {
        let h1 = hash_for_lookup("same@email.com", "tenant_a_key");
        let h2 = hash_for_lookup("same@email.com", "tenant_b_key");
        assert_ne!(h1, h2);
    }

    #[test]
    fn decrypt_with_wrong_tenant_key() {
        let ct = encrypt("data", "correct_tenant_key", MK).unwrap();
        assert!(decrypt(&ct, "wrong_tenant_key", MK).is_err());
    }

    #[test]
    fn decrypt_with_wrong_master_key() {
        let ct = encrypt("data", TK, "correct_master_key").unwrap();
        assert!(decrypt(&ct, TK, "wrong_master_key").is_err());
    }

    #[test]
    fn cross_tenant_replay_fails() {
        // AAD binding: ciphertext from tenant_a must not decrypt as tenant_b
        let ct = encrypt("secret", "tenant_key_aaa", MK).unwrap();
        assert!(decrypt(&ct, "tenant_key_bbb", MK).is_err());
    }

    #[test]
    fn decrypt_garbage_input() {
        assert!(decrypt("not_valid_base64!!!", TK, MK).is_err());
        assert!(decrypt("", TK, MK).is_err());
        assert!(decrypt("dGVzdA==", TK, MK).is_err());
    }

    #[test]
    fn short_tenant_key_rejected() {
        assert!(encrypt("data", "short", MK).is_err());
    }

    #[test]
    fn short_master_key_rejected() {
        assert!(encrypt("data", TK, "short").is_err());
    }

    #[test]
    fn empty_key_rejected() {
        assert!(encrypt("data", "", MK).is_err());
        assert!(encrypt("data", TK, "").is_err());
    }

    #[test]
    fn encrypt_very_long_string() {
        let long = "x".repeat(100_000);
        let ct = encrypt(&long, TK, MK).unwrap();
        assert_eq!(decrypt(&ct, TK, MK).unwrap(), long);
    }

    #[test]
    fn encrypt_special_characters() {
        let special = "Hello 🌍! こんにちは <script>alert('xss')</script> \n\t\"quotes\"";
        let ct = encrypt(special, TK, MK).unwrap();
        assert_eq!(decrypt(&ct, TK, MK).unwrap(), special);
    }

    #[test]
    fn encrypt_keys_with_special_chars() {
        let ct = encrypt("data", "key with spaces & symbols!", "master_key_🔑").unwrap();
        assert_eq!(
            decrypt(&ct, "key with spaces & symbols!", "master_key_🔑").unwrap(),
            "data"
        );
    }
}
