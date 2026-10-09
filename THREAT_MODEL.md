# WhistleDrop — Threat Model & STRIDE Analysis

This document outlines the formal threat model, STRIDE taxonomy, adversary capabilities, and defense mitigations implemented across WhistleDrop.

---

## 1. Adversary Capabilities & Threat Actors

| Threat Actor | Capabilities & Access | Primary Goals | Countermeasures |
| :--- | :--- | :--- | :--- |
| **Passive Network Wiretapper** | Observes ISP transit, TLS metadata, edge ingress packets | Deanonymize informants via IP/traffic correlation | IP-stripping Nginx edge, no client identifiers logged, Strict TLS & CSP, no case code in URLs |
| **Storage Snooper / DB Dumper** | Obtains cold PostgreSQL database dump and storage backups | Read confidential whistleblower disclosures | ALEE AES-256-GCM envelope encryption, KEK separation, AAD context binding, salt-hashed case codes |
| **Rogue / Curious Moderator** | Legitimate moderator credentials with read access | Access unassigned cases or bulk export data without notice | Strict audit logging, Merkle transparency leaves, rate limits, no access to destroyed keys |
| **Compelled Platform Operator** | Subpoena / National Security Letter / Server seizure | Hand over past deleted evidence or tamper with audit history | Forward-secure cryptographic erasure (destroyed DEKs), RFC 6962 append-only Merkle tree, Warrant Canary |
| **Malicious Informant / Saboteur** | Submits malicious payloads, polyglot files, floods API | Compromise review team systems or exhaust infrastructure | Async ClamAV malware scanning, MIME magic byte validation, Redis token-bucket rate limiting, 25MB body limit |

---

## 2. STRIDE Threat Analysis

### A. Spoofing
- **Threat:** Impersonating an anonymous reporter to read case timeline or messages.
  - **Mitigation:** Case codes are generated via CSPRNG with 256 bits of entropy and verified using Argon2id with unique salts.
- **Threat:** Forging moderator authorization tokens.
  - **Mitigation:** JWTs are cryptographically signed with high-entropy secret, bound to an active database session ID, and checked against the Redis token revocation blacklist on every request.

### B. Tampering
- **Threat:** Modifying encrypted case descriptions or timeline messages in the database.
  - **Mitigation:** AES-256-GCM AEAD requires a 128-bit authentication tag. Any single-bit modification fails decryption closed.
- **Threat:** Splicing encrypted fields into another case or object.
  - **Mitigation:** Authenticated Additional Data (AAD) cryptographically binds the ciphertext to `(report_id, object_type, object_id, field_name, aad_version)`.
- **Threat:** Altering or rewriting audit logs.
  - **Mitigation:** RFC 6962 append-only Merkle tree commits cryptographic leaf hashes atomically with database transactions. Ed25519 Signed Tree Heads (STH) provide cryptographically signed transparency commitments binding tree state.

### C. Repudiation
- **Threat:** Moderator denies taking an action (e.g. status transition, case rejection, key destruction).
  - **Mitigation:** All administrative and moderation actions append immutable audit log records and publish Merkle transparency leaves.

### D. Information Disclosure
- **Threat:** Exposing whistleblower identity through browser telemetry or HTTP URLs.
  - **Mitigation:** Strict frontend architectural rule: No case codes in browser URLs, query parameters, navigation state, or web storage (`localStorage`/`sessionStorage`).
- **Threat:** Residual evidence lingering on disk after case resolution or withdrawal.
  - **Mitigation:** Unified Cryptographic Erasure: The per-case Data Encryption Key (DEK) is zeroized and marked destroyed, immediately rendering all payloads unrecoverable, followed by multi-pass filesystem shredding.

### E. Denial of Service
- **Threat:** Flooding submission endpoints or storage drives with giant files.
  - **Mitigation:** Dual-tier rate limiting (Nginx edge + Redis sorted-set Lua script). 25MB upload limit. Evidence files quarantined before ClamAV approval.

### F. Elevation of Privilege
- **Threat:** Unprivileged moderator triggering emergency unseal or key re-wrapping.
  - **Mitigation:** Role-based access control (`MODERATOR` vs `ADMIN`). Emergency unseal strictly requires `ADMIN` role and verified TOTP multi-factor proof.

---

## 3. Webhook Architecture & DNS Rebinding Security Boundaries

### Threat Characterization: DNS Rebinding (TOCTOU)
WhistleDrop supports outbound webhook notifications to external endpoints registered by administrators.
- **Registration Time Verification:** At endpoint registration (`POST /api/v1/moderator/webhooks`), `ssrf_validator.resolve_and_validate_destination` resolves the target hostname and blocks any destination resolving to private/loopback/cloud-metadata networks (including IPv4-mapped IPv6, RFC 1918, RFC 3927 link-local, and AWS/GCP metadata endpoints).
- **Dispatch Time Verification:** Before outbound HTTP transmission in `webhook_dispatcher_service`, `resolve_and_validate_destination` is re-executed to catch static DNS updates.

### Residual Risk & Architectural Boundary
Because Python's standard `httpx.AsyncClient` manages socket-level connection establishment separately from pre-flight `getaddrinfo` calls, a microscopic Time-of-Check to Time-of-Use (TOCTOU) window exists if an adversary controls an authoritative DNS server with an ultralow TTL (e.g., 0 seconds) that returns a legitimate public IP during validation, but returns an internal IP (`127.0.0.1` or `169.254.169.254`) on the subsequent connection attempt by `httpx`.

### Compensating Controls & Production Deployment Requirements
1. **Administrative Access Control:** Webhook endpoints can only be created by authenticated administrators (`ADMIN` role with active session). Anonymous informants cannot register webhook endpoints.
2. **Network-Level Egress Filtering:** In production deployments, egress traffic from the `api` container must be constrained by host firewall rules (e.g. `iptables` or cloud security groups) to explicitly block outbound connections to `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and `169.254.169.254/32`.
3. **Internal Container Isolation:** Database (`db`), cache (`redis`), and scanner (`clamav`) containers reside on an isolated internal Docker bridge (`internal_net`) without published host ports.
