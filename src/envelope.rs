use crate::{
    cipher::{decrypt_raw, encrypt_raw},
    error::{HefestoError, Result},
    kdf::{derive_key, generate_salt, SALT_SIZE},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use zeroize::Zeroizing;

/// Payload version byte. Increment when the on-disk format changes so that
/// older ciphertexts can be identified and rejected with a clear error.
///
/// v0x02 — 32-byte salts; outer AEAD AAD = version ‖ salt₁ ‖ salt₂ ‖ tenant_key
const PAYLOAD_VERSION: u8 = 0x02;

// version(1) + salt_1(32) + salt_2(32) + nonce_2(12) + tag_2(16) + nonce_1(12) + tag_1(16)
const MIN_PAYLOAD_BYTES: usize = 1 + SALT_SIZE * 2 + 12 + 16 + 12 + 16;

pub(crate) fn envelope_encrypt(
    plaintext: &str,
    tenant_key: &str,
    master_key: &str,
) -> Result<String> {
    let salt_1 = generate_salt();
    let key_1 = derive_key(tenant_key, &salt_1)?;
    // inner layer has no AAD — the outer layer authenticates all structural fields
    let layer_1 = encrypt_raw(plaintext.as_bytes(), &key_1, &[])?;

    let salt_2 = generate_salt();
    let key_2 = derive_key(master_key, &salt_2)?;

    // Outer AAD covers every field that lives outside the AEAD envelope:
    // version, both salts, and the tenant identity. This prevents undetected
    // tampering of salt_1/salt_2 and cross-tenant replay in one binding.
    let outer_aad = build_outer_aad(PAYLOAD_VERSION, &salt_1, &salt_2, tenant_key);
    let layer_2 = encrypt_raw(&layer_1, &key_2, &outer_aad)?;

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

    let salt_end = 1 + SALT_SIZE;
    let salts_end = 1 + SALT_SIZE * 2;

    let salt_1: [u8; SALT_SIZE] = bytes[1..salt_end]
        .try_into()
        .map_err(|_| HefestoError::InvalidPayload)?;
    let salt_2: [u8; SALT_SIZE] = bytes[salt_end..salts_end]
        .try_into()
        .map_err(|_| HefestoError::InvalidPayload)?;
    let layer_2 = &bytes[salts_end..];

    // Reconstruct the same outer AAD used during encryption.
    // Use bytes[0] (the actual version in the payload) so this stays correct
    // if future versions introduce a separate decrypt branch.
    let outer_aad = build_outer_aad(bytes[0], &salt_1, &salt_2, tenant_key);

    let key_2 = derive_key(master_key, &salt_2)?;
    // layer_1 is zeroized on drop — it contains the inner ciphertext
    let layer_1: Zeroizing<Vec<u8>> = decrypt_raw(layer_2, &key_2, &outer_aad)?;

    let key_1 = derive_key(tenant_key, &salt_1)?;
    // plaintext_bytes is zeroized on drop before the String copy is returned
    let plaintext_bytes: Zeroizing<Vec<u8>> = decrypt_raw(&*layer_1, &key_1, &[])?;

    std::str::from_utf8(&*plaintext_bytes)
        .map(str::to_owned)
        .map_err(|_| HefestoError::InvalidUtf8)
}

/// Builds the outer AEAD additional data: version ‖ salt₁ ‖ salt₂ ‖ tenant_key.
fn build_outer_aad(version: u8, salt_1: &[u8], salt_2: &[u8], tenant_key: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + salt_1.len() + salt_2.len() + tenant_key.len());
    aad.push(version);
    aad.extend_from_slice(salt_1);
    aad.extend_from_slice(salt_2);
    aad.extend_from_slice(tenant_key.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_basic() {
        let ct = envelope_encrypt("hello@example.com", "tenant_key_16bytes", "master_key_16bytes").unwrap();
        let pt = envelope_decrypt(&ct, "tenant_key_16bytes", "master_key_16bytes").unwrap();
        assert_eq!(pt, "hello@example.com");
    }

    #[test]
    fn non_deterministic() {
        let ct1 = envelope_encrypt("same", "tenant_key_16bytes", "master_key_16bytes").unwrap();
        let ct2 = envelope_encrypt("same", "tenant_key_16bytes", "master_key_16bytes").unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn wrong_tenant_key_fails() {
        let ct = envelope_encrypt("data", "correct_tenant_key_", "master_key_16bytes").unwrap();
        assert!(envelope_decrypt(&ct, "wrong_tenant_key__", "master_key_16bytes").is_err());
    }

    #[test]
    fn wrong_master_key_fails() {
        let ct = envelope_encrypt("data", "tenant_key_16bytes", "correct_master_key_").unwrap();
        assert!(envelope_decrypt(&ct, "tenant_key_16bytes", "wrong_master_key__").is_err());
    }

    #[test]
    fn both_keys_wrong_fails() {
        let ct = envelope_encrypt("data", "tenant_key_16bytes", "master_key_16bytes").unwrap();
        assert!(envelope_decrypt(&ct, "bad_tenant_key_16b", "bad_master_key_16b").is_err());
    }

    #[test]
    fn tenant_aad_binding() {
        let ct = envelope_encrypt("secret", "tenant_key_aaaaaaa", "master_key_16bytes").unwrap();
        assert!(envelope_decrypt(&ct, "tenant_key_bbbbbbb", "master_key_16bytes").is_err());
    }

    #[test]
    fn salt_1_tampering_detected() {
        // With the outer AAD covering salt_1, flipping a salt_1 bit must be detected.
        let ct_b64 = envelope_encrypt("data", "tenant_key_16bytes", "master_key_16bytes").unwrap();
        let mut bytes = base64::engine::general_purpose::STANDARD.decode(&ct_b64).unwrap();
        // salt_1 starts at byte 1
        bytes[2] ^= 0xFF;
        let tampered = base64::engine::general_purpose::STANDARD.encode(&bytes);
        assert!(envelope_decrypt(&tampered, "tenant_key_16bytes", "master_key_16bytes").is_err());
    }

    #[test]
    fn tampered_payload_fails() {
        let mut ct = envelope_encrypt("data", "tenant_key_16bytes", "master_key_16bytes").unwrap();
        let mid = ct.len() / 2;
        let replacement = if &ct[mid..mid + 1] == "A" { "B" } else { "A" };
        ct.replace_range(mid..mid + 1, replacement);
        assert!(envelope_decrypt(&ct, "tenant_key_16bytes", "master_key_16bytes").is_err());
    }

    #[test]
    fn empty_string_roundtrip() {
        let ct = envelope_encrypt("", "tenant_key_16bytes", "master_key_16bytes").unwrap();
        let pt = envelope_decrypt(&ct, "tenant_key_16bytes", "master_key_16bytes").unwrap();
        assert_eq!(pt, "");
    }

    #[test]
    fn long_string_roundtrip() {
        let long = "a".repeat(10_000);
        let ct = envelope_encrypt(&long, "tenant_key_16bytes", "master_key_16bytes").unwrap();
        let pt = envelope_decrypt(&ct, "tenant_key_16bytes", "master_key_16bytes").unwrap();
        assert_eq!(pt, long);
    }

    #[test]
    fn unicode_roundtrip() {
        let unicode = "こんにちは 🔥 مرحبا";
        let ct = envelope_encrypt(unicode, "tenant_key_16bytes", "master_key_16bytes").unwrap();
        let pt = envelope_decrypt(&ct, "tenant_key_16bytes", "master_key_16bytes").unwrap();
        assert_eq!(pt, unicode);
    }

    #[test]
    fn payload_starts_with_version_byte() {
        let ct = envelope_encrypt("data", "tenant_key_16bytes", "master_key_16bytes").unwrap();
        let bytes = base64::engine::general_purpose::STANDARD.decode(&ct).unwrap();
        assert_eq!(bytes[0], PAYLOAD_VERSION);
        assert_eq!(PAYLOAD_VERSION, 0x02);
    }
}
