use crate::error::{HefestoError, Result};
use argon2::Argon2;
use rand::RngCore;
use zeroize::Zeroizing;

/// Salt size in bytes. 32 bytes (256 bits) exceeds the NIST minimum of 128 bits.
pub(crate) const SALT_SIZE: usize = 32;

const ARGON2_MEMORY_KB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const ARGON2_OUTPUT_LEN: usize = 32;

/// Returns a consistently-parameterised Argon2id instance used by both key
/// derivation and password hashing, ensuring uniform hardness across the crate.
pub(crate) fn make_argon2() -> Argon2<'static> {
    let params = argon2::Params::new(
        ARGON2_MEMORY_KB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(ARGON2_OUTPUT_LEN),
    )
    .expect("Argon2 parameters are valid compile-time constants");
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
}

pub(crate) fn derive_key(secret: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    make_argon2()
        .hash_password_into(secret.as_bytes(), salt, &mut *key)
        .map_err(|e| HefestoError::KeyDerivationFailed(e.to_string()))?;
    Ok(key)
}

pub(crate) fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_key_is_32_bytes() {
        let key = derive_key("my_secret", &[1u8; 32]).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn same_inputs_produce_same_key() {
        let salt = [42u8; 32];
        let k1 = derive_key("password", &salt).unwrap();
        let k2 = derive_key("password", &salt).unwrap();
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let k1 = derive_key("password", &[1u8; 32]).unwrap();
        let k2 = derive_key("password", &[2u8; 32]).unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn different_secrets_produce_different_keys() {
        let salt = [1u8; 32];
        let k1 = derive_key("secret_a", &salt).unwrap();
        let k2 = derive_key("secret_b", &salt).unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn salts_are_unique() {
        assert_ne!(generate_salt(), generate_salt());
    }

    #[test]
    fn salt_is_correct_size() {
        assert_eq!(generate_salt().len(), SALT_SIZE);
        assert_eq!(SALT_SIZE, 32);
    }
}
