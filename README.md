# Hefesto

[![CI](https://github.com/lu-jl/hefesto/actions/workflows/ci.yml/badge.svg)](https://github.com/lu-jl/hefesto/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/hefesto.svg)](https://crates.io/crates/hefesto)
[![docs.rs](https://docs.rs/hefesto/badge.svg)](https://docs.rs/hefesto)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Field-level encryption for multi-tenant applications. Each encrypted value requires two independent keys to decrypt — one owned by the tenant, one by the server. Losing either key makes the data unreadable.

Built on AES-256-GCM + Argon2id. No key management — bring your own keys.

## Install

```toml
[dependencies]
hefesto = "1.0.2"
```

## Quickstart

```rust
use hefesto::HefestoError;

fn save_user(email: &str, tenant_key: &str, master_key: &str) -> Result<(), HefestoError> {
    // Encrypt — different ciphertext every call (random nonce + salt)
    let encrypted = hefesto::encrypt(email, tenant_key, master_key)?;

    // Deterministic hash for searching without decrypting
    let lookup = hefesto::hash_for_lookup(email, tenant_key);

    // store both in DB: (email_encrypted, email_lookup)
    Ok(())
}

fn find_user(email: &str, tenant_key: &str, master_key: &str) -> Result<String, HefestoError> {
    // Hash to find the row, then decrypt to read it
    let lookup = hefesto::hash_for_lookup(email, tenant_key);
    // SELECT email_encrypted FROM users WHERE email_lookup = ?

    let row_encrypted = /* ... */ String::new();
    hefesto::decrypt(&row_encrypted, tenant_key, master_key)
}

// Passwords: one-way only, never decrypted
fn register(password: &str) -> Result<String, HefestoError> {
    hefesto::hash_password(password) // → "$argon2id$v=19$..."
}

fn login(password: &str, stored_hash: &str) -> bool {
    hefesto::verify_password(password, stored_hash)
}
```

## Why two keys?

A single-key encryption scheme means whoever controls the server controls all tenant data. Two independent keys create a meaningful separation:

| Scenario | Single-key | Hefesto |
|---|---|---|
| Server compromised, master key leaked | All tenants exposed | Attacker still needs each tenant's key |
| Tenant key leaked | N/A | Attacker still needs the master key |
| Both keys leaked | — | Data exposed |
| DB dumped, no keys | Offline brute-force possible | Argon2id makes it expensive per-tenant |

The tenant key also acts as [AAD](https://en.wikipedia.org/wiki/Authenticated_encryption) on the outer encryption layer. A ciphertext encrypted for tenant A will fail to decrypt even if someone supplies the correct master key with a different tenant key — it can't be moved between tenants silently.

## DB schema pattern

For each encrypted field, store two columns:

```sql
-- email_encrypted: the ciphertext (changes every write)
-- email_lookup:    deterministic hash for WHERE queries (indexed)
ALTER TABLE users
    ADD COLUMN email_encrypted TEXT    NOT NULL,
    ADD COLUMN email_lookup    TEXT    NOT NULL,
    ADD INDEX  idx_email_lookup (email_lookup);
```

```rust
// Write
let encrypted = hefesto::encrypt(email, tenant_key, master_key)?;
let lookup    = hefesto::hash_for_lookup(email, tenant_key);
// INSERT INTO users (email_encrypted, email_lookup) VALUES (?, ?)

// Search
let lookup = hefesto::hash_for_lookup(search_email, tenant_key);
// SELECT * FROM users WHERE email_lookup = ? AND tenant_id = ?

// Read
let email = hefesto::decrypt(&row.email_encrypted, tenant_key, master_key)?;
```

> `hash_for_lookup` uses HMAC-SHA256 keyed on `tenant_key`. Two tenants with the same email produce different lookup hashes — no cross-tenant correlation from the DB.

## Performance

Each `encrypt` or `decrypt` call runs Argon2id **twice** (once per key) with 64 MB RAM and 3 iterations. This is intentional — it makes offline brute-force attacks against stolen ciphertexts expensive.

**Typical latency:** ~200–400 ms per call on server hardware.

This is appropriate for:
- Encrypting/decrypting individual fields at request time
- Background jobs that process one record at a time

This is not appropriate for:
- Bulk imports of thousands of rows inline — offload to a background worker queue
- Hot paths that run on every HTTP request — encrypt at write time, cache the plaintext in memory for the request lifetime

## Error handling

```rust
use hefesto::HefestoError;

match hefesto::decrypt(&ciphertext, tenant_key, master_key) {
    Ok(plaintext)                        => { /* use it */ }
    Err(HefestoError::DecryptionFailed)  => { /* wrong key or tampered data */ }
    Err(HefestoError::InvalidPayload)    => { /* corrupted, truncated, or wrong version */ }
    Err(HefestoError::InvalidKey(msg))   => { /* key too short — at least 8 bytes required */ }
    Err(e)                               => { /* KeyDerivationFailed, InvalidUtf8 (rare) */ }
}
```

| Error | Cause |
|---|---|
| `DecryptionFailed` | Wrong key or payload was tampered with |
| `InvalidPayload` | Corrupted, truncated, or unrecognized payload version |
| `InvalidKey(msg)` | Key shorter than 8 bytes |
| `InvalidUtf8` | Decrypted bytes are not valid UTF-8 |
| `KeyDerivationFailed` | Argon2id internal error (rare) |
| `PasswordHashFailed` | Argon2id internal error (rare) |

## Key requirements

Keys must be at least 8 bytes. Recommended: 32+ random bytes.

```bash
openssl rand -hex 32
# e3b0c44298fc1c149afbf4c8996fb924...
```

- **Tenant key** — one per tenant. Store in tenant config or secrets manager.
- **Master key** — one per deployment. Store as an env var. Rotating it requires re-encrypting all fields.
- **Never log keys.** They must not appear in error messages, traces, or stack dumps.
- **Use random keys, not passwords.** Human-chosen strings have low entropy. If your keys come from user passwords, hash them with Argon2id first before passing to Hefesto.

## How it works

```
encrypt(value, tenant_key, master_key)
├── salt_1 = OsRng[16]
├── key_1  = Argon2id(tenant_key, salt_1) → [u8; 32]
├── layer_1 = AES-256-GCM(value, key_1, nonce=OsRng[12])
│
├── salt_2 = OsRng[16]
├── key_2  = Argon2id(master_key, salt_2) → [u8; 32]
├── layer_2 = AES-256-GCM(layer_1, key_2, nonce=OsRng[12], aad=tenant_key)
│             ↑ tenant_key bound as AAD: wrong tenant_key → auth tag fails
│
└── output = Base64( 0x01 | salt_1 | salt_2 | layer_2 )
                     ↑ version byte — reserved for future algorithm changes
```

All derived keys are held in `Zeroizing<[u8; 32]>` — wiped from memory on drop.

## Security properties

| Property | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM — 256-bit key, IND-CPA secure |
| Integrity / tamper detection | GCM authentication tag — any bit flip fails decryption |
| Key stretching | Argon2id — memory-hard, resists GPU/ASIC brute-force |
| Non-deterministic ciphertext | Random 16-byte salt + 12-byte nonce per operation |
| Key isolation | Two independent KDF invocations with independent salts |
| Tenant isolation | tenant_key as AEAD associated data on the outer layer |
| Memory safety | `zeroize` wipes key material from RAM after use |
| Lookup privacy | HMAC-SHA256(value, tenant_key) — no cross-tenant correlation |
| Forward compatibility | Version byte in payload |

## License

MIT
