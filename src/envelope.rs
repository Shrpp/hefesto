use crate::{
    cipher::{decrypt_raw, encrypt_raw},
    error::{HefestoError, Result},
    kdf::{derive_key, generate_salt},
};
use base64::{engine::general_purpose::STANDARD, Engine};

const PAYLOAD_VERSION: u8 = 0x01;
const SALT_SIZE: usize = 16;
// version(1) + salt_1(16) + salt_2(16) + nonce_2(12) + tag(16) + nonce_1(12) + tag(16)
const MIN_PAYLOAD_BYTES: usize = 1 + SALT_SIZE * 2 + 12 + 16 + 12 + 16;

pub(crate) fn envelope_encrypt(
    plaintext: &str,
    tenant_key: &str,
    master_key: &str,
) -> Result<String> {
    let salt_1 = generate_salt();
    let key_1 = derive_key(tenant_key, &salt_1)?;
    // inner layer has no AAD — the outer layer binds the tenant context
    let layer_1 = encrypt_raw(plaintext.as_bytes(), &key_1, &[])?;

    let salt_2 = generate_salt();
    let key_2 = derive_key(master_key, &salt_2)?;
    // outer layer uses tenant_key as AAD — binds this ciphertext to this tenant
    let layer_2 = encrypt_raw(&layer_1, &key_2, tenant_key.as_bytes())?;

    let mut payload = Vec::with_capacity(1 + SALT_SIZE * 2 + layer_2.len());
    payload.push(PAYLOAD_VERSION);
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

    if bytes[0] != PAYLOAD_VERSION {
        return Err(HefestoError::InvalidPayload);
    }

    let salt_1: [u8; 16] = bytes[1..17]
        .try_into()
        .map_err(|_| HefestoError::InvalidPayload)?;
    let salt_2: [u8; 16] = bytes[17..33]
        .try_into()
        .map_err(|_| HefestoError::InvalidPayload)?;
    let layer_2 = &bytes[33..];

    let key_2 = derive_key(master_key, &salt_2)?;
    // must supply same tenant_key AAD used during encryption
    let layer_1 = decrypt_raw(layer_2, &key_2, tenant_key.as_bytes())?;

    let key_1 = derive_key(tenant_key, &salt_1)?;
    let plaintext_bytes = decrypt_raw(&layer_1, &key_1, &[])?;

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
        let ct = envelope_encrypt("data", "correct_tenant", "master_key").unwrap();
        assert!(envelope_decrypt(&ct, "wrong_tenant", "master_key").is_err());
    }

    #[test]
    fn wrong_master_key_fails() {
        let ct = envelope_encrypt("data", "tenant_key", "correct_master").unwrap();
        assert!(envelope_decrypt(&ct, "tenant_key", "wrong_master").is_err());
    }

    #[test]
    fn both_keys_wrong_fails() {
        let ct = envelope_encrypt("data", "tenant_key", "master_key").unwrap();
        assert!(envelope_decrypt(&ct, "bad_tenant_k", "bad_master_k").is_err());
    }

    #[test]
    fn tenant_aad_binding() {
        // ciphertext encrypted for tenant_a must not decrypt as tenant_b
        // even with correct master_key
        let ct = envelope_encrypt("secret", "tenant_key_a", "master_key").unwrap();
        assert!(envelope_decrypt(&ct, "tenant_key_b", "master_key").is_err());
    }

    #[test]
    fn tampered_payload_fails() {
        let mut ct = envelope_encrypt("data", "tenant_key", "master_key").unwrap();
        let mid = ct.len() / 2;
        let replacement = if &ct[mid..mid + 1] == "A" { "B" } else { "A" };
        ct.replace_range(mid..mid + 1, replacement);
        assert!(envelope_decrypt(&ct, "tenant_key", "master_key").is_err());
    }

    #[test]
    fn empty_string_roundtrip() {
        let ct = envelope_encrypt("", "tenant_key", "master_key").unwrap();
        let pt = envelope_decrypt(&ct, "tenant_key", "master_key").unwrap();
        assert_eq!(pt, "");
    }

    #[test]
    fn long_string_roundtrip() {
        let long = "a".repeat(10_000);
        let ct = envelope_encrypt(&long, "tenant_key", "master_key").unwrap();
        let pt = envelope_decrypt(&ct, "tenant_key", "master_key").unwrap();
        assert_eq!(pt, long);
    }

    #[test]
    fn unicode_roundtrip() {
        let unicode = "こんにちは 🔥 مرحبا";
        let ct = envelope_encrypt(unicode, "tenant_key", "master_key").unwrap();
        let pt = envelope_decrypt(&ct, "tenant_key", "master_key").unwrap();
        assert_eq!(pt, unicode);
    }

    #[test]
    fn payload_starts_with_version_byte() {
        let ct = envelope_encrypt("data", "tenant_key", "master_key").unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&ct)
            .unwrap();
        assert_eq!(bytes[0], PAYLOAD_VERSION);
    }
}
