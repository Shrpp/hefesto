# Hefesto

[![CI](https://github.com/lu-jl/hefesto/actions/workflows/ci.yml/badge.svg)](https://github.com/lu-jl/hefesto/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/hefesto.svg)](https://crates.io/crates/hefesto)
[![docs.rs](https://docs.rs/hefesto/badge.svg)](https://docs.rs/hefesto)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Double envelope encryption for multi-tenant applications. Encrypts field values with two independent keys (tenant + server master), using AES-256-GCM and Argon2id.

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
hefesto = "0.1.0"
```

```rust
use hefesto::HefestoError;

// Encrypt a field for DB storage (different output each call)
let ciphertext = hefesto::encrypt(
    "user@example.com",
    "tenant_secret_key",
    "master_server_key",
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

## How it works

```
encrypt(value, tenant_key, master_key):

  salt_1  = OsRng (16 bytes)
  key_1   = Argon2id(tenant_key, salt_1)  →  32 bytes
  layer_1 = AES-256-GCM(value, key_1)     →  nonce_1 || ciphertext_1

  salt_2  = OsRng (16 bytes)
  key_2   = Argon2id(master_key, salt_2)  →  32 bytes
  layer_2 = AES-256-GCM(layer_1, key_2)  →  nonce_2 || ciphertext_2

  output  = Base64( salt_1 || salt_2 || layer_2 )
```

Both keys are required to decrypt. Compromising one key does not expose any data.

## Security decisions

| Decision | Reason |
|---|---|
| AES-256-GCM (AEAD) | Encrypts and authenticates in one step — tampering is detected explicitly |
| Argon2id for KDF | Memory-hard — brute-force is expensive in both time and RAM |
| Random salt per operation | Same secret → different derived key each time |
| Random nonce per operation | Same plaintext → different ciphertext each time |
| `Zeroizing` on all derived keys | Key material is wiped from RAM when it goes out of scope |
| HMAC-SHA256 for lookups | No cross-tenant correlation; stronger than plain SHA-256 |
| Two independent layers | One compromised key does not break the other |
| `verify_password` returns `bool` | Never leaks why verification failed |

## License

MIT
