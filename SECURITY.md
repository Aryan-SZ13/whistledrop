# WhistleDrop — Security Policy & Cryptographic Architecture

WhistleDrop is a privacy-first anonymous reporting platform designed to protect journalists, sources, and anonymous informants under hostile threat environments.

---

## 1. Cryptographic Standards & Specifications

WhistleDrop avoids custom or untested primitives, relying strictly on modern, industry-standard cryptographic algorithms:

| Layer | Standard / Primitive | Key Length / Parameters | Purpose |
| :--- | :--- | :--- | :--- |
| **Case Codes** | CSPRNG + Argon2id | 256-bit entropy, 64MB memory, 3 iterations | Anonymous bearer credential derivation |
| **Payload Encryption (ALEE)** | AES-256-GCM | 256-bit DEK, 96-bit random IV, 128-bit tag | Application-level envelope encryption for descriptions and sensitive updates |
| **Key Encryption Keys (KEK)** | AES-256-GCM Keyring | 256-bit AES keys with explicit key versioning | Envelope wrapping of per-case DEKs |
| **Transparency Log** | RFC 6962 Merkle Tree + SHA-256 | 256-bit SHA-256 digests | Immutable, append-only tamper-evident audit tree |
| **Tree Head Signatures** | Ed25519 (RFC 8032) | 256-bit private seed / 256-bit public key | Cryptographically signed transparency commitments for Signed Tree Heads (STH) |
| **Moderator Sessions** | Signed JWT (HS256) + Redis Blacklist | 256-bit secret, 15m expiration | Ephemeral moderator authorization with instant revocation |
| **Multi-Factor Auth (MFA)** | TOTP (RFC 6238) | SHA-1, 6-digit, 30s window, AES-GCM encrypted secrets | Administrator & moderator step-up verification |

---

## 2. Core Security Invariants

1. **Privacy-First Anonymous Reporting:**
   - **Application-level anonymity:** No reporter accounts, registration, or persistent identifying credentials.
   - **Application logging privacy:** No IP addresses, user agents, or device fingerprints are logged or stored in application telemetry.
   - **Infrastructure-level privacy assumptions:** Reverse proxy edge infrastructure strips identifying client headers (`X-Forwarded-For`, `X-Real-IP`, and `Forwarded`).
   - Case codes are never placed into URLs, query parameters, route parameters, or browser persistence (`localStorage`, `sessionStorage`, `indexedDB`).
2. **Cryptographic Erasure:**
   - Cryptographic unrecoverability within the application's key-management boundary: Deletion of sensitive evidence or case withdrawal zeroizes the per-case Data Encryption Key (DEK), rendering all associated ciphertexts cryptographically unrecoverable within the application's key-management boundary, followed by multi-pass secure filesystem shredding.
3. **Authenticated Additional Data (AAD) Context Binding:**
   - Every encrypted field is cryptographically bound to its `report_id`, `object_type`, `object_id`, `field_name`, and `aad_version`.
   - Ciphertexts cannot be swapped, moved, or spliced across reports or database rows without failing authentication tag verification.
4. **Emergency Seal & Warrant Canary:**
   - Cryptographically signed warrant canaries require periodic administrative check-in. Canary expiration signals operational disruption or administrative absence.
   - Emergency Seal state immediately freezes all plaintext decryption, export generation, and key destruction, while keeping anonymous report ingestion active to preserve incoming evidence.
   - Emergency Unseal strictly mandates dual-factor proof and multi-party quorum approval.

---

## 3. Vulnerability Reporting

If you discover a potential vulnerability or security flaw in WhistleDrop, please report it privately:

- **Email:** `security@whistledrop.org` (or configured organization contact)
- **PGP Fingerprint:** `[CONFIGURED_ORG_PGP_KEY]`
- **Response SLA:** Acknowledgment within 24 hours; initial assessment and triage within 72 hours.
- **Coordinated Disclosure:** We adhere to a 90-day coordinated vulnerability disclosure policy. Please do not create public GitHub issues for security vulnerabilities.
