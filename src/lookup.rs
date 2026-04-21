use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn hash_for_lookup(value: &str, tenant_key: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(tenant_key.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(value.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let h1 = hash_for_lookup("user@example.com", "tenant_key");
        let h2 = hash_for_lookup("user@example.com", "tenant_key");
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_values_different_hashes() {
        let h1 = hash_for_lookup("a@example.com", "key");
        let h2 = hash_for_lookup("b@example.com", "key");
        assert_ne!(h1, h2);
    }

    #[test]
    fn different_tenant_keys_different_hashes() {
        let h1 = hash_for_lookup("user@example.com", "tenant_a");
        let h2 = hash_for_lookup("user@example.com", "tenant_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn output_is_valid_hex() {
        let h = hash_for_lookup("test", "key");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(h.len(), 64);
    }
}
