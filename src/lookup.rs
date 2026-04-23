use crate::error::{HefestoError, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn hash_for_lookup(value: &str, tenant_key: &str) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(tenant_key.as_bytes())
        .map_err(|e| HefestoError::InvalidKey(e.to_string()))?;
    mac.update(value.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let h1 = hash_for_lookup("user@example.com", "tenant_key").unwrap();
        let h2 = hash_for_lookup("user@example.com", "tenant_key").unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_values_different_hashes() {
        let h1 = hash_for_lookup("a@example.com", "key").unwrap();
        let h2 = hash_for_lookup("b@example.com", "key").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn different_tenant_keys_different_hashes() {
        let h1 = hash_for_lookup("user@example.com", "tenant_a").unwrap();
        let h2 = hash_for_lookup("user@example.com", "tenant_b").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn output_is_valid_hex() {
        let h = hash_for_lookup("test", "key").unwrap();
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(h.len(), 64);
    }
}
