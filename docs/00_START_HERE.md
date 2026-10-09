# WhistleDrop — Documentation & Architectural Map
## *Speak Without Being Seen*

Welcome to the technical engineering documentation for **WhistleDrop**, an open-source, cryptographically hardened backend platform for anonymous whistleblowing and incident disclosures.

---

## 1. Executive Overview in 30 Seconds

### What Problem WhistleDrop Solves
Employees and informants reporting corporate corruption, security vulnerabilities, or workplace misconduct face severe retaliation risks. Conventional ticketing systems and web forms collect IP addresses, session cookies, browser telemetry, or user accounts, leaving informants exposed to subpoena, internal log inspection, or database breaches.

### The Core Solution
WhistleDrop decouples reporting from identity:
1. **Zero-Identity Intake**: Submissions collect no username, email, phone number, IP address, or user-agent headers.
2. **Bearer Case Codes**: The server returns a 256-bit cryptographically secure case code once. The server stores only an `HMAC-SHA256` digest, so even if the database is leaked, the plaintext case codes cannot be reversed.
3. **Application-Level Envelope Encryption (ALEE)**: Case narratives are encrypted before persistence using per-case AES-256-GCM data encryption keys (DEKs) wrapped under server key encryption keys (KEKs).
4. **RFC 6962 Merkle Transparency**: Submissions are committed to an append-only cryptographic tree with Signed Tree Heads (STH), proving that records have not been secretly deleted or altered.
5. **Cryptographic Erasure**: Whistleblowers can withdraw a report at any time. The server destroys the per-case DEK, rendering ciphertexts mathematically unrecoverable.

---

## 2. Reading Roadmap: Choose Your Depth

| Goal | Time Required | Recommended Reading |
| :--- | :---: | :--- |
| **High-Level Understanding** | **30 seconds** | Read the executive overview above and inspect the [System Context Diagram](01_ARCHITECTURE_AND_COMPONENTS.md#1-system-context-diagram). |
| **Workflow & Security Model** | **5 minutes** | Read [Report Lifecycle Workflows](02_REPORT_LIFECYCLE.md) and [Security Mechanisms Visualized](03_SECURITY_DEEP_DIVE.md). |
| **Deep Architectural Review** | **30 minutes** | Follow the complete guide sequence below, inspect source files, and run the test and benchmark suites. |

---

## 3. Recommended Document Reading Sequence

1. **[00_START_HERE.md](00_START_HERE.md)** *(This Document)*: Mission, reading paths, and documentation index.
2. **[01_ARCHITECTURE_AND_COMPONENTS.md](01_ARCHITECTURE_AND_COMPONENTS.md)**: Visual architecture diagrams (System Context, Component Structure, and Deployment Topology) with real source file mappings.
3. **[02_REPORT_LIFECYCLE.md](02_REPORT_LIFECYCLE.md)**: Sequence diagrams tracing submission, case tracking, moderator triage, and the strict state transition machine.
4. **[03_SECURITY_DEEP_DIVE.md](03_SECURITY_DEEP_DIVE.md)**: Visual, 10-point pedagogical deep dives covering Case Code HMACs, Envelope Encryption (ALEE), Cryptographic Erasure, Merkle Trees, Emergency Sealing, and Warrant Canaries.
5. **[04_RELIABILITY_AND_OPERATIONS.md](04_RELIABILITY_AND_OPERATIONS.md)**: Concurrency controls, transactional outbox leases, fail-closed rate limiters, reverse-proxy trust boundaries, and disaster recovery.
6. **[05_BENCHMARKS_AND_PERFORMANCE.md](05_BENCHMARKS_AND_PERFORMANCE.md)**: Empirical latency percentiles, operation throughput, methodology, and generated charts.
7. **[06_PRIVACY_PREFLIGHT.md](06_PRIVACY_PREFLIGHT.md)**: Client-side identification prevention, architectural evaluation of why deterministic rules beat client ML, zero-network guarantees, and empirical benchmarks.
8. **[REQUIREMENTS_TRACEABILITY.md](REQUIREMENTS_TRACEABILITY.md)**: Bidirectional mapping of every GDG assignment requirement, bonus feature, and test evidence.

---

## 4. How to Use the Diagrams

All architectural, sequence, and state diagrams are authored in **Mermaid** directly inside Markdown files. They are:
- **Version-Controlled**: Maintained directly alongside the code in Git.
- **Inspectable**: Rendered natively on GitHub and in Markdown previewers.
- **Accurate**: Every node and flow matches tested Python/SQL/TypeScript implementations.

---

## 5. Where to Find Tests, Code & Benchmarks

| Artifact | Location in Repository | Description |
| :--- | :--- | :--- |
| **Backend Core** | `app/` | FastAPI application, models, schemas, and cryptographic services. |
| **Frontend App** | `frontend/` | React/TypeScript SPA with memory-only case tracking, zero URL leakage, and Privacy Preflight. |
| **Test Suites** | `tests/` | 343 automated backend tests across 19 test modules. |
| **Frontend Tests** | `frontend/src/__tests__/` | 35 vitest unit and browser security audit tests across 4 test files. |
| **Privacy Preflight Harness** | `scripts/evaluate_privacy_preflight.py` | 58-sample synthetic evaluation measuring accuracy, latency, and generating trade-off charts. |
| **Disaster Recovery** | `scripts/recovery_drill.py` | 5-tier simulated cryptographic consistency drill. |
| **Benchmark Suite** | `scripts/benchmark.py` | Standalone script measuring latency percentiles and throughput. |
| **Benchmark Report** | `BENCHMARKS.md` | Empirical latency tables (p50, p95, p99) and methodology. |
| **Database Migrations**| `alembic/versions/` | 11 sequential, reproducible database schema revisions. |
