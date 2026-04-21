use crate::error::{HefestoError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use zeroize::Zeroizing;

pub(crate) fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

pub(crate) fn encrypt_raw(
    plaintext: &[u8],
    key: &Zeroizing<[u8; 32]>,
    aad: &[u8],
) -> Result<Vec<u8>> {
    let nonce_bytes = generate_nonce();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&**key));

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| HefestoError::EncryptionFailed)?;

    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub(crate) fn decrypt_raw(data: &[u8], key: &Zeroizing<[u8; 32]>, aad: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(HefestoError::PayloadTooShort {
            expected: 12,
            got: data.len(),
        });
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&**key));

    cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| HefestoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::derive_key;

    fn test_key() -> Zeroizing<[u8; 32]> {
        derive_key("test_secret", &[1u8; 16]).unwrap()
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = b"hello hefesto";
        let encrypted = encrypt_raw(plaintext, &key, &[]).unwrap();
        let decrypted = decrypt_raw(&encrypted, &key, &[]).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn same_input_different_output() {
        let key = test_key();
        let e1 = encrypt_raw(b"same", &key, &[]).unwrap();
        let e2 = encrypt_raw(b"same", &key, &[]).unwrap();
        assert_ne!(e1, e2);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = derive_key("key_a", &[1u8; 16]).unwrap();
        let key2 = derive_key("key_b", &[1u8; 16]).unwrap();
        let encrypted = encrypt_raw(b"secret", &key1, &[]).unwrap();
        assert!(decrypt_raw(&encrypted, &key2, &[]).is_err());
    }

    #[test]
    fn tampered_data_fails() {
        let key = test_key();
        let mut encrypted = encrypt_raw(b"secret", &key, &[]).unwrap();
        encrypted[15] ^= 0xFF;
        assert!(decrypt_raw(&encrypted, &key, &[]).is_err());
    }

    #[test]
    fn too_short_data_fails() {
        let key = test_key();
        assert!(decrypt_raw(&[0u8; 5], &key, &[]).is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = test_key();
        let encrypted = encrypt_raw(b"secret", &key, b"tenant_a").unwrap();
        assert!(decrypt_raw(&encrypted, &key, b"tenant_b").is_err());
    }

    #[test]
    fn correct_aad_succeeds() {
        let key = test_key();
        let encrypted = encrypt_raw(b"secret", &key, b"my_tenant").unwrap();
        let decrypted = decrypt_raw(&encrypted, &key, b"my_tenant").unwrap();
        assert_eq!(decrypted, b"secret");
    }
}
