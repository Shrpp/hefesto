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

pub fn encrypt(value: &str, tenant_key: &str, master_key: &str) -> Result<String> {
    validate_key(tenant_key, "tenant_key")?;
    validate_key(master_key, "master_key")?;
    envelope::envelope_encrypt(value, tenant_key, master_key)
}

pub fn decrypt(ciphertext: &str, tenant_key: &str, master_key: &str) -> Result<String> {
    validate_key(tenant_key, "tenant_key")?;
    validate_key(master_key, "master_key")?;
    envelope::envelope_decrypt(ciphertext, tenant_key, master_key)
}

pub fn hash_password(password: &str) -> Result<String> {
    password::hash_password(password)
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    password::verify_password(password, hash)
}

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
