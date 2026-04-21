use crate::{
    cipher::{decrypt_raw, encrypt_raw},
    error::{HefestoError, Result},
    kdf::{derive_key, generate_salt},
};
use base64::{engine::general_purpose::STANDARD, Engine};

const SALT_SIZE: usize = 16;
const MIN_PAYLOAD_BYTES: usize = SALT_SIZE * 2 + 12 + 12 + 1;

pub(crate) fn envelope_encrypt(
    plaintext: &str,
    tenant_key: &str,
    master_key: &str,
) -> Result<String> {
    let salt_1 = generate_salt();
    let key_1 = derive_key(tenant_key, &salt_1)?;
    let layer_1 = encrypt_raw(plaintext.as_bytes(), &key_1)?;

    let salt_2 = generate_salt();
    let key_2 = derive_key(master_key, &salt_2)?;
    let layer_2 = encrypt_raw(&layer_1, &key_2)?;

    let mut payload = Vec::with_capacity(SALT_SIZE * 2 + layer_2.len());
    payload.extend_from_slice(&salt_1);
    payload.extend_from_slice(&salt_2);
    payload.extend_from_slice(&layer_2);

    Ok(STANDARD.encode(&payload))
}

pub(crate) fn envelope_decrypt(
    ciphertext: &str,
    tenant_key: &str,
    master_key: &str,
) -> Result<String> {
    let bytes = STANDARD
        .decode(ciphertext)
        .map_err(|_| HefestoError::InvalidPayload)?;

    if bytes.len() < MIN_PAYLOAD_BYTES {
        return Err(HefestoError::PayloadTooShort {
            expected: MIN_PAYLOAD_BYTES,
            got: bytes.len(),
        });
    }

    let salt_1: [u8; 16] = bytes[0..16]
        .try_into()
        .map_err(|_| HefestoError::InvalidPayload)?;
    let salt_2: [u8; 16] = bytes[16..32]
        .try_into()
        .map_err(|_| HefestoError::InvalidPayload)?;
    let layer_2 = &bytes[32..];

    let key_2 = derive_key(master_key, &salt_2)?;
    let layer_1 = decrypt_raw(layer_2, &key_2)?;

    let key_1 = derive_key(tenant_key, &salt_1)?;
    let plaintext_bytes = decrypt_raw(&layer_1, &key_1)?;

    String::from_utf8(plaintext_bytes).map_err(|_| HefestoError::InvalidUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_basic() {
        let ct = envelope_encrypt("hello@example.com", "tenant_key", "master_key").unwrap();
        let pt = envelope_decrypt(&ct, "tenant_key", "master_key").unwrap();
        assert_eq!(pt, "hello@example.com");
    }

    #[test]
    fn non_deterministic() {
        let ct1 = envelope_encrypt("same", "tenant_key", "master_key").unwrap();
        let ct2 = envelope_encrypt("same", "tenant_key", "master_key").unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn wrong_tenant_key_fails() {
        let ct = envelope_encrypt("data", "correct_tenant", "master").unwrap();
        assert!(envelope_decrypt(&ct, "wrong_tenant", "master").is_err());
    }

    #[test]
    fn wrong_master_key_fails() {
        let ct = envelope_encrypt("data", "tenant", "correct_master").unwrap();
        assert!(envelope_decrypt(&ct, "tenant", "wrong_master").is_err());
    }

    #[test]
    fn both_keys_wrong_fails() {
        let ct = envelope_encrypt("data", "tenant", "master").unwrap();
        assert!(envelope_decrypt(&ct, "bad_tenant", "bad_master").is_err());
    }

    #[test]
    fn tampered_payload_fails() {
        let mut ct = envelope_encrypt("data", "tenant", "master").unwrap();
        let mid = ct.len() / 2;
        let replacement = if &ct[mid..mid + 1] == "A" { "B" } else { "A" };
        ct.replace_range(mid..mid + 1, replacement);
        assert!(envelope_decrypt(&ct, "tenant", "master").is_err());
    }

    #[test]
    fn empty_string_roundtrip() {
        let ct = envelope_encrypt("", "tenant", "master").unwrap();
        let pt = envelope_decrypt(&ct, "tenant", "master").unwrap();
        assert_eq!(pt, "");
    }

    #[test]
    fn long_string_roundtrip() {
        let long = "a".repeat(10_000);
        let ct = envelope_encrypt(&long, "tenant", "master").unwrap();
        let pt = envelope_decrypt(&ct, "tenant", "master").unwrap();
        assert_eq!(pt, long);
    }

    #[test]
    fn unicode_roundtrip() {
        let unicode = "こんにちは 🔥 مرحبا";
        let ct = envelope_encrypt(unicode, "tenant", "master").unwrap();
        let pt = envelope_decrypt(&ct, "tenant", "master").unwrap();
        assert_eq!(pt, unicode);
    }
}
