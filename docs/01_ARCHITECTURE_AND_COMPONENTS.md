# WhistleDrop — Visual Architecture Guide
## Systems Context, Components & Deployment Topology

---

## 1. System Context Diagram (Diagram A)

The following diagram defines the physical and operational boundaries of WhistleDrop. It highlights the distinction between the reporter's client environment, the edge anonymizer, the application boundary, and persistent storage tiers:

```mermaid
graph TD
    subgraph ClientTiers["Client Tier (Untrusted / In-Memory Only)"]
        Reporter["Anonymous Reporter<br/>(No Account / Memory-Only Code)"]
        Moderator["Investigator / Moderator<br/>(Argon2id + JWT + MFA TOTP)"]
    end

    subgraph EdgeBoundary["Edge Ingress & Privacy Perimeter"]
        Nginx["Nginx Reverse Proxy (:80 / :443)<br/>• Strips X-Forwarded-For & Client IP<br/>• Enforces Strict CSP & Referrer-Policy<br/>• Zero-IP Access Logging Format"]
    end

    subgraph AppBoundary["WhistleDrop Application Boundary (FastAPI Core)"]
        API["FastAPI ASGI Server (:8000)<br/>• Input Validation (Pydantic v2)<br/>• RBAC Authorization Tiers<br/>• Fail-Closed Sliding Window Limiter"]

        CryptoEngine["Cryptographic Subsystem<br/>• CSPRNG Case Code (256-bit)<br/>• HMAC-SHA256 Digest Derivation<br/>• ALEE (AES-256-GCM + AAD Binding)<br/>• Keyring Rotation & Zeroization"]

        TransparencyCore["RFC 6962 Merkle Engine<br/>• Canonical Serialization<br/>• Atomic Contiguous Indexing<br/>• STH Ed25519 Signatures"]

        AsyncWorkers["In-Process Async Workers<br/>• Transactional Outbox Dispatch<br/>• Periodic Antivirus Reconciliation<br/>• Quarantine Sweeps (Advisory Locks)"]
    end

    subgraph StorageTier["Persistence & Infrastructure Tier (Private Network)"]
        PG[("PostgreSQL 16 Database<br/>• Reports & Digests (No Plaintext Code)<br/>• Encrypted Payloads & AAD Meta<br/>• Merkle Leaves & Tree State<br/>• Outbox Events & Audit Trails")]
        
        RedisCache[("Redis 7 In-Memory Cache<br/>• Ephemeral Rate Limit Counters<br/>• Distributed Probe Safeguards<br/>• Outage Fails Closed")]

        FileStorage[("Evidence Storage Disk<br/>• quarantine/ (Unverified / Scanned)<br/>• approved/ (Promoted / AES Encrypted)<br/>• Local Partitioned Storage")]

        ClamAV["ClamAV Daemon (:3310)<br/>• Streaming INSTREAM Antivirus Scans<br/>• Automatic Quarantine Shredding"]
    end

    Reporter -->|"HTTPS POST (Payload / Code in Body)"| Nginx
    Moderator -->|"HTTPS (Bearer JWT + MFA TOTP)"| Nginx
    Nginx -->|"HTTP (Clean Forwarded Headers)"| API
    
    API <--> CryptoEngine
    API <--> TransparencyCore
    API <--> AsyncWorkers

    API -->|"Asyncpg Transactions"| PG
    API -->|"Sliding Window Counters"| RedisCache
    API -->|"Multipart File Uploads"| FileStorage
    AsyncWorkers -->|"TCP INSTREAM Scan"| ClamAV
    AsyncWorkers -->|"Advisory Lock DB Leases"| PG
```

---

## 2. Component Architecture (Diagram B)

Every service, router, and schema maps directly to concrete source files within `app/`:

```mermaid
graph TD
    subgraph Presentation["Presentation & API Routing (app/api/v1/endpoints)"]
        R_Reports["reports.py<br/>Intake, Case Tracking, Messages"]
        R_Mod["moderator.py<br/>Triage, Status Updates, Quorum, Unseal"]
        R_Canary["canary.py<br/>Public STH, Canary Statements"]
        R_Evidence["evidence.py<br/>Multipart Uploads, Verification"]
    end

    subgraph ServiceLayer["Business Logic & Security Services (app/services)"]
        S_Report["report_service.py<br/>Submission & Least-Privilege Tracking"]
        S_Crypto["payload_encryption_service.py<br/>ALEE DEK/KEK Encryption & Erasure"]
        S_Transp["transparency_service.py<br/>Merkle Leaf Commitments & Proofs"]
        S_Canary["canary_service.py<br/>Canary Publishing, Dead-Man & Sealing"]
        S_Mod["moderator_service.py<br/>Lifecycle State Machine & OCC Triage"]
        S_Limit["rate_limiter.py<br/>Atomic Lua Rate-Limiting Engine"]
        S_Evidence["evidence_service.py<br/>Magic Validation, ClamAV, Quarantine"]
    end

    subgraph DataModels["Domain Models & Storage Schemas (app/models)"]
        M_Report["report.py & enums.py<br/>Report, Status, Category, CaseCodeDigest"]
        M_Crypto["encryption.py<br/>CaseEncryptionKey (Wrapped DEKs)"]
        M_Merkle["transparency.py<br/>MerkleTreeState & MerkleLeaves"]
        M_Canary["canary.py<br/>WarrantCanary & SystemSecurityState"]
        M_Evidence["evidence.py<br/>EvidenceAttachment & ShredStatus"]
    end

    R_Reports --> S_Report
    R_Reports --> S_Limit
    R_Reports --> S_Evidence
    R_Mod --> S_Mod
    R_Mod --> S_Crypto
    R_Mod --> S_Canary
    R_Canary --> S_Canary
    R_Evidence --> S_Evidence

    S_Report --> S_Crypto
    S_Report --> S_Transp
    S_Report --> M_Report
    S_Crypto --> M_Crypto
    S_Transp --> M_Merkle
    S_Canary --> M_Canary
    S_Mod --> M_Report
    S_Evidence --> M_Evidence
```

### Component Responsibility & Invariant Matrix

| Component | Responsibility | Implementation Location | Critical Security Invariant |
| :--- | :--- | :--- | :--- |
| **Intake Controller** | Parses and validates public report submissions. | [`app/api/v1/endpoints/reports.py`](../app/api/v1/endpoints/reports.py) | Never extracts or logs client IP; forbids extra fields. |
| **Report Service** | Coordinates report persistence, encryption, and leaf generation. | [`app/services/report_service.py`](../app/services/report_service.py) | Plaintext case code is never saved; least-privilege projection on tracking. |
| **ALEE Crypto Engine**| Manages envelope encryption, per-case DEKs, and key destruction. | [`app/services/payload_encryption_service.py`](../app/services/payload_encryption_service.py) | AAD binding to record ID; zeroization of DEK on withdrawal. |
| **Transparency Service**| Appends canonical leaf commitments and computes STH root hashes. | [`app/services/transparency_service.py`](../app/services/transparency_service.py) | Contiguous leaf indices allocated under row locks; deterministic binary leaves. |
| **Canary & Seal Service**| Ed25519 canary issuance, dead-man check-ins, and emergency sealing. | [`app/services/canary_service.py`](../app/services/canary_service.py) | Blocks decryption, export, and destruction when sealed; unseal requires fresh TOTP. |
| **Moderator Service** | Manages incident review queue, transitions, and public updates. | [`app/services/moderator_service.py`](../app/services/moderator_service.py) | Strict lifecycle transitions; terminal case closure; optimistic concurrency control. |
| **Evidence Service** | Validates MIME magic, coordinates ClamAV scans, and manages quarantine. | [`app/services/evidence_service.py`](../app/services/evidence_service.py) | Strict 25MB file ceiling; unpromoted infected files are shredded immediately. |
| **Rate Limiter** | Ephemeral Redis sliding-window abuse prevention. | [`app/services/rate_limiter.py`](../app/services/rate_limiter.py) | Fails closed on Redis outage; never uses case codes in Redis keys. |

---

## 3. Production Deployment Topology (Diagram C)

The production stack utilizes private Docker network isolation, pinning reverse-proxy trust strictly to the static IP of the Nginx container:

```mermaid
graph TD
    Internet((Public Internet))

    subgraph HostEnv["Production Host Boundary (Linux / Docker Engine)"]
        subgraph PublicNet["Public Ingress Bridge (public_net)"]
            NginxContainer["Nginx Container<br/>• Static Ingress: :80 / :443<br/>• TLS Termination (TLS 1.2 / 1.3)<br/>• Pinned Static IP: 172.28.0.10"]
        end

        subgraph PrivateNet["Isolated Internal Bridge (internal_net: 172.28.0.0/24)"]
            APIContainer["FastAPI Application Container (api:8000)<br/>• Non-Root User: whistledrop (UID 10001)<br/>• Trusted Proxy CIDR: 172.28.0.10/32<br/>• Healthcheck: curl http://localhost:8000/api/v1/health"]
            
            DBContainer["PostgreSQL Container (db:5432)<br/>• Least-Privilege DML User: whistledrop_app<br/>• Volume: postgres_prod_data"]
            
            RedisContainer["Redis Container (redis:6379)<br/>• Protected Mode & Password Auth<br/>• Volume: redis_prod_data"]
            
            ClamAVContainer["ClamAV Container (clamav:3310)<br/>• Stream Scanning Service"]
        end
    end

    Internet -->|"Port 80 / 443"| NginxContainer
    NginxContainer -->|"Proxy Pass (172.28.0.10 -> api:8000)"| APIContainer
    APIContainer -->|"Private SQL (5432)"| DBContainer
    APIContainer -->|"Private Redis Protocol (6379)"| RedisContainer
    APIContainer -->|"Private TCP Stream (3310)"| ClamAVContainer

    classDef unverified stroke:#f43f5e,stroke-width:2px,stroke-dasharray: 5 5;
    class HostEnv unverified;
```

> **Operational Boundary Disclosure**:
> The deployment topology above reflects the verified architecture codified in `Dockerfile`, `docker-compose.prod.yml`, and `deploy/nginx/nginx.conf`.
> **Local Environment Limitation**: Because the local evaluation host does not have a running Docker daemon, live multi-container deployment, image building, and production TLS handshakes are marked **BLOCKED — NOT VERIFIED** in the compliance matrix.
