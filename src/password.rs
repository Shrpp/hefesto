use crate::error::{HefestoError, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, SaltString},
    Argon2, PasswordHasher, PasswordVerifier,
};

pub(crate) fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);

    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| HefestoError::PasswordHashFailed(e.to_string()))
}

pub(crate) fn verify_password(password: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let hash = hash_password("my_password").unwrap();
        assert!(verify_password("my_password", &hash));
    }

    #[test]
    fn wrong_password_fails() {
        let hash = hash_password("correct_password").unwrap();
        assert!(!verify_password("wrong_password", &hash));
    }

    #[test]
    fn hashes_are_unique() {
        let h1 = hash_password("password").unwrap();
        let h2 = hash_password("password").unwrap();
        assert_ne!(h1, h2);
        assert!(verify_password("password", &h1));
        assert!(verify_password("password", &h2));
    }

    #[test]
    fn invalid_hash_returns_false() {
        assert!(!verify_password("password", "not_a_valid_hash"));
        assert!(!verify_password("password", ""));
    }

    #[test]
    fn hash_starts_with_argon2id() {
        let hash = hash_password("test").unwrap();
        assert!(hash.starts_with("$argon2id$"));
    }
}
