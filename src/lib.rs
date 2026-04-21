mod cipher;
mod envelope;
mod error;
mod kdf;
mod lookup;
mod password;

pub use error::HefestoError;
use error::Result;

pub fn encrypt(value: &str, tenant_key: &str, master_key: &str) -> Result<String> {
    envelope::envelope_encrypt(value, tenant_key, master_key)
}

pub fn decrypt(ciphertext: &str, tenant_key: &str, master_key: &str) -> Result<String> {
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

    #[test]
    fn full_roundtrip() {
        let ct = encrypt("sensitive_data", "tenant", "master").unwrap();
        assert_eq!(decrypt(&ct, "tenant", "master").unwrap(), "sensitive_data");
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
        let ct1 = encrypt("data", "tk", "mk").unwrap();
        let ct2 = encrypt("data", "tk", "mk").unwrap();
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
        let ct = encrypt("data", "correct_tenant", "master").unwrap();
        assert!(decrypt(&ct, "wrong_tenant", "master").is_err());
    }

    #[test]
    fn decrypt_with_wrong_master_key() {
        let ct = encrypt("data", "tenant", "correct_master").unwrap();
        assert!(decrypt(&ct, "tenant", "wrong_master").is_err());
    }

    #[test]
    fn decrypt_garbage_input() {
        assert!(decrypt("not_valid_base64!!!", "tenant", "master").is_err());
        assert!(decrypt("", "tenant", "master").is_err());
        assert!(decrypt("dGVzdA==", "tenant", "master").is_err());
    }

    #[test]
    fn encrypt_very_long_string() {
        let long = "x".repeat(100_000);
        let ct = encrypt(&long, "tenant", "master").unwrap();
        assert_eq!(decrypt(&ct, "tenant", "master").unwrap(), long);
    }

    #[test]
    fn encrypt_special_characters() {
        let special = "Hello 🌍! こんにちは <script>alert('xss')</script> \n\t\"quotes\"";
        let ct = encrypt(special, "tenant", "master").unwrap();
        assert_eq!(decrypt(&ct, "tenant", "master").unwrap(), special);
    }

    #[test]
    fn encrypt_keys_with_special_chars() {
        let ct = encrypt("data", "key with spaces & symbols!", "master_🔑").unwrap();
        assert_eq!(
            decrypt(&ct, "key with spaces & symbols!", "master_🔑").unwrap(),
            "data"
        );
    }
}
