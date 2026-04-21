# Hefesto

[![CI](https://github.com/lu-jl/hefesto/actions/workflows/ci.yml/badge.svg)](https://github.com/lu-jl/hefesto/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/hefesto.svg)](https://crates.io/crates/hefesto)
[![docs.rs](https://docs.rs/hefesto/badge.svg)](https://docs.rs/hefesto)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Double envelope encryption for multi-tenant applications. Encrypts field values with two independent keys (tenant + server master) using AES-256-GCM and Argon2id.

## What it does

- **Field encryption** — encrypt sensitive DB fields (emails, names, documents) with per-tenant isolation
- **Password hashing** — one-way Argon2id hashes, not reversible
- **Lookup hashing** — deterministic HMAC-SHA256 so you can `WHERE email_lookup = ?` without decrypting

## What it does not do

- Key management — bring your own keys
- File or stream encryption — strings and bytes only
- Network protocols or TLS

## Quickstart

```toml
[dependencies]
hefesto = "1.0.2"
```

```rust
use hefesto::HefestoError;

// Encrypt a field for DB storage (different output each call)
let ciphertext = hefesto::encrypt(
    "user@example.com",
    "tenant_secret_key",   // at least 8 bytes
    "master_server_key",   // at least 8 bytes
)?;

// Decrypt
let plaintext = hefesto::decrypt(
    &ciphertext,
    "tenant_secret_key",
    "master_server_key",
)?;
assert_eq!(plaintext, "user@example.com");

// Password hashing (one-way)
let hash = hefesto::hash_password("my_password")?;
assert!(hefesto::verify_password("my_password", &hash));

// Deterministic hash for DB lookups
// Same input + same key → always same output
let lookup = hefesto::hash_for_lookup("user@example.com", "tenant_secret_key");
// Store alongside the encrypted field, query with: WHERE email_lookup = ?
```

## Real-world DB usage

For each sensitive field, store two columns:

```sql
ALTER TABLE users ADD COLUMN email_encrypted TEXT;   -- hefesto::encrypt output
ALTER TABLE users ADD COLUMN email_lookup     TEXT;  -- hefesto::hash_for_lookup output, indexed
```

```rust
// Write
let email = "user@example.com";
let encrypted = hefesto::encrypt(email, &tenant_key, &master_key)?;
let lookup    = hefesto::hash_for_lookup(email, &tenant_key);
// INSERT INTO users (email_encrypted, email_lookup) VALUES (?, ?)

// Search
let lookup = hefesto::hash_for_lookup("user@example.com", &tenant_key);
// SELECT email_encrypted FROM users WHERE email_lookup = ?

// Read
let email = hefesto::decrypt(&row.email_encrypted, &tenant_key, &master_key)?;
```

## Error handling

```rust
use hefesto::HefestoError;

match hefesto::decrypt(&ciphertext, &tenant_key, &master_key) {
    Ok(plaintext) => { /* use it */ }
    Err(HefestoError::DecryptionFailed)  => { /* wrong key or tampered data */ }
    Err(HefestoError::InvalidPayload)    => { /* corrupted or truncated payload */ }
    Err(HefestoError::InvalidKey(msg))   => { /* key too short */ }
    Err(e) => { /* other */ }
}
```

| Error | When |
|---|---|
| `DecryptionFailed` | Wrong key or payload was tampered with |
| `InvalidPayload` | Corrupted, truncated, or wrong format |
| `InvalidKey` | Key shorter than 8 bytes |
| `KeyDerivationFailed` | Argon2id internal error (rare) |
| `InvalidUtf8` | Decrypted bytes are not valid UTF-8 |
| `PasswordHashFailed` | Argon2id internal error (rare) |

## Key recommendations

- **Use random keys, not passwords.** Keys should be random byte strings (e.g. `openssl rand -hex 32`), not human-chosen passwords. Argon2id is used as KDF but works best with high-entropy inputs.
- **Minimum length**: 8 bytes enforced. Recommended: 32 bytes or more.
- **Tenant keys**: one per tenant, stored in your tenant config or secrets manager.
- **Master key**: one per deployment, stored in env var or secrets manager. Rotating it requires re-encrypting all fields.
- **Never log keys.** The keys passed to `encrypt`/`decrypt` must not appear in logs or error messages.

```bash
# Generate a suitable key
openssl rand -hex 32
# → e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

## Performance

Each call to `encrypt` or `decrypt` runs Argon2id twice (once per key). This is intentional — it makes brute-forcing stolen ciphertexts expensive. Expect **~200–400 ms per operation** on typical server hardware (64 MB RAM, 3 iterations).

This makes Hefesto suitable for encrypting fields at write/read time, but not for high-frequency operations (e.g. encrypting every row in a bulk import without batching).

If throughput is critical, derive your keys once per request and cache them for the request lifetime. Key caching is the caller's responsibility.

## How it works

```
encrypt(value, tenant_key, master_key):

  salt_1  = OsRng (16 bytes)
  key_1   = Argon2id(tenant_key, salt_1)  →  32 bytes
  layer_1 = AES-256-GCM(value, key_1)

  salt_2  = OsRng (16 bytes)
  key_2   = Argon2id(master_key, salt_2)  →  32 bytes
  layer_2 = AES-256-GCM(layer_1, key_2, aad=tenant_key)
             ↑ tenant_key is bound as AAD — decryption fails
               if a different tenant_key is supplied

  output  = Base64( 0x01 || salt_1 || salt_2 || layer_2 )
             ↑ version byte for future algorithm upgrades
```

Both keys are required to decrypt. Compromising one key does not expose any data. The AAD binding ensures a ciphertext encrypted for tenant A cannot be decrypted by tenant B even with the correct master key.

## Security decisions

| Decision | Reason |
|---|---|
| AES-256-GCM (AEAD) | Encrypts and authenticates in one step — tampering detected explicitly |
| Argon2id for KDF | Memory-hard — brute-force is expensive in both time and RAM |
| Random salt per operation | Same secret → different derived key each time |
| Random nonce per operation | Same plaintext → different ciphertext each time |
| `Zeroizing` on all derived keys | Key material wiped from RAM on drop |
| HMAC-SHA256 for lookups | No cross-tenant correlation; stronger than plain SHA-256 |
| Two independent layers | One compromised key does not break the other |
| tenant_key as AAD on outer layer | Prevents cross-tenant ciphertext replay even with master key |
| Version byte in payload | Future-proof: cipher can change without breaking existing ciphertexts |
| Minimum key length (8 bytes) | Rejects obvious mistakes like empty keys |
| `verify_password` returns `bool` | Never leaks why verification failed |

## License

MIT
