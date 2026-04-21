# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately to: lucius.2906@gmail.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive a response within 72 hours. If the issue is confirmed, a patch will be released before public disclosure.

## Scope

The following are considered vulnerabilities in Hefesto:

- Incorrect authentication tag verification in AES-256-GCM (tampered data not detected)
- Key material leaking outside `Zeroizing<>` wrappers
- Deterministic output from `encrypt` (nonce or salt reuse)
- Correlation between tenants via `hash_for_lookup`
- Timing side-channels in `verify_password`

The following are **out of scope**:

- Key management (Hefesto does not store or rotate keys)
- Weak keys passed by the caller
- Vulnerabilities in upstream dependencies (report to their maintainers)
