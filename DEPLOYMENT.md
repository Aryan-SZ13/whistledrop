# WhistleDrop — Production Deployment Guide & Operations Manual

This document specifies the target architecture, security posture, configuration requirements, and operational procedures for deploying WhistleDrop in a production environment.

---

## 1. Production Topology & Network Isolation

WhistleDrop enforces defense-in-depth through multi-tier network segregation:

```
[Public Internet]
       │
       ▼ (Port 80 / 443)
┌─────────────────────────────────────────────────────────────┐
│ Edge / Reverse Proxy: Nginx (public_net & internal_net)    │
│  - Anonymization: Strips X-Forwarded-For, X-Real-IP, etc.   │
│  - Zero Logging: No reporter IPs or user agents retained    │
│  - Static Asset Serving: Pre-built Vite/React frontend      │
│  - Upstream Proxy: Rate-limited API routes                  │
└──────────────────────────────┬──────────────────────────────┘
                               │ (Strict internal bridge: internal_net)
       ┌───────────────────────┼──────────────────────────────┐
       ▼                       ▼                              ▼
┌──────────────┐      ┌─────────────────┐            ┌─────────────────┐
│ FastAPI API  │◄────►│ PostgreSQL 16   │            │ Redis 7         │
│  - Non-Root  │      │  - Envelope DEKs│            │  - Token Black- │
│  - 4 Workers │      │  - Merkle Logs  │            │    list         │
│  - ALEE Enc. │      │  - Outbox Events│            │  - Rate Limits  │
└──────┬───────┘      └─────────────────┘            └─────────────────┘
       │
       ▼
┌──────────────┐
│ ClamAV       │
│  - Asynchro- │
│    nous Scan │
└──────────────┘
```

### Security Invariants
1. **Zero External Access to Data Stores**: PostgreSQL, Redis, and ClamAV do not publish host ports and exist solely on the isolated `internal_net` bridge.
2. **Reporter Anonymization**: Nginx strictly zeroes `X-Forwarded-For`, `X-Real-IP`, and `Forwarded` headers before routing requests to FastAPI. Nginx access logs omit client IP addresses.
3. **Unprivileged Container Execution**: The application container executes under user `whistledrop:whistledrop` (UID 10001, GID 10001) with read-only root permissions outside of designated local volumes.
4. **Restricted Reverse Proxy Trust**: Ingress proxy headers to FastAPI are trusted strictly from the pinned Nginx container static IP (`172.28.0.10/32` on internal bridge `172.28.0.0/24`) and loopback (`127.0.0.1`). Unrelated internal containers (e.g. database, cache, or antivirus) cannot spoof client identities.

---

## 2. Environment Variables & Secret Configuration

Create a secure `.env.production` file outside version control.

| Variable | Description | Example / Format |
| :--- | :--- | :--- |
| `ENVIRONMENT` | Target environment mode | `production` |
| `DEBUG` | FastAPI debugging flag | `false` |
| `POSTGRES_USER` | PostgreSQL application user (least privilege) | `whistledrop_app` |
| `POSTGRES_PASSWORD`| PostgreSQL application user password | *High-entropy 32+ char secret* |
| `POSTGRES_DB` | Database name | `whistledrop_prod` |
| `REDIS_PASSWORD` | Redis authentication password | *High-entropy 32+ char secret* |
| `JWT_SECRET` | Secret for moderator session JWTs | `openssl rand -hex 32` |
| `CASE_CODE_SECRET` | Secret for case code digest derivation | `openssl rand -hex 32` |
| `PAYLOAD_KEK_ACTIVE_VERSION` | Active KEK version index | `1` |
| `PAYLOAD_KEK_KEYRING` | JSON dictionary of 256-bit AES KEKs | `{"1": "<64-hex-chars>"}` |
| `EXPORT_SIGNING_KEY_ED25519_PRIVATE` | Ed25519 private key seed (hex) | `64 hex characters (32 bytes)` |
| `EXPORT_SIGNING_KEY_ED25519_PUBLIC` | Ed25519 public key (hex) | `64 hex characters (32 bytes)` |
| `CANARY_SIGNING_KEY_ED25519_PRIVATE` | Ed25519 canary private key seed (hex) | `64 hex characters (32 bytes)` |
| `TRANSPARENCY_STH_SIGNING_KEY_ID` | Key identifier for STH signatures | `whistledrop-prod-2026-v1` |
| `EVIDENCE_STORAGE_PATH` | Path to evidence attachments | `/app/storage/evidence` |

### Database User Separation (Least Privilege)
In production environments, distinct PostgreSQL roles must be enforced:
1. **Migration / Admin Role (`whistledrop_admin`)**: Owns the schema and runs Alembic migrations (`CREATE TABLE`, `ALTER TABLE`, `DROP`, etc.).
2. **Application Role (`whistledrop_app`)**: Restricted strictly to operational DML (`SELECT`, `INSERT`, `UPDATE`, `DELETE`). It possesses NO DDL permissions (`CREATE`, `DROP`, `ALTER`).

```sql
-- Create application role with restricted privileges
CREATE USER whistledrop_app WITH ENCRYPTED PASSWORD 'your_app_password';
GRANT CONNECT ON DATABASE whistledrop_prod TO whistledrop_app;
GRANT USAGE ON SCHEMA public TO whistledrop_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO whistledrop_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO whistledrop_app;
```

### Background Processing & Distributed Lock Architecture
WhistleDrop uses an **in-process async background task architecture** driven by FastAPI's lifespan lifecycle rather than external celery/phantom workers.
- Evidence reconciliation and quarantine sweeps run in-process on schedule.
- Multi-worker safety across container replicas is guaranteed via **PostgreSQL Advisory Locks** (`pg_try_advisory_lock`), ensuring only one worker node performs reconciliation tasks concurrently. No extra background worker container is needed or deployed.

---

## 3. Cryptographic Key Generation Recipes

Execute the following commands in an isolated environment to generate production secrets:

### A. JWT Secret & Case Code Secret
```bash
openssl rand -hex 32  # JWT_SECRET
openssl rand -hex 32  # CASE_CODE_SECRET
```

### B. Payload KEK Keyring (AES-256-GCM KEKs)
```bash
python3 -c "
import json, secrets
keyring = {'1': secrets.token_hex(32)}
print('PAYLOAD_KEK_KEYRING=' + json.dumps(keyring))
"
```

### C. Ed25519 Transparency & Export Signing Keys
```bash
python3 -c "
from cryptography.hazmat.primitives.asymmetric import ed25519
priv = ed25519.Ed25519PrivateKey.generate()
priv_bytes = priv.private_bytes_raw()
pub_bytes = priv.public_key().public_bytes_raw()
print('EXPORT_SIGNING_KEY_ED25519_PRIVATE=' + priv_bytes.hex())
print('EXPORT_SIGNING_KEY_ED25519_PUBLIC=' + pub_bytes.hex())
"
```

### D. TLS Certificate Policy (Testing vs Production CA)
> [!WARNING]
> The default self-signed certificate located in `deploy/nginx/certs/` (`whistledrop.crt` / `whistledrop.key`) is generated exclusively for local testing, integration validation, and Docker healthcheck bootstrapping.
> 
> **It is NOT a publicly trusted certificate and MUST NOT be used in a live public deployment.**
> For production environments, mount valid certificates issued by a publicly trusted Certificate Authority (e.g., Let's Encrypt / ACME, DigiCert, Sectigo) into `/etc/nginx/certs/whistledrop.crt` and `/etc/nginx/certs/whistledrop.key`.

---

## 4. Production Deployment Checklist

### Step 1: Build Frontend Distribution
```bash
cd frontend
npm ci
npm run build
cd ..
```

### Step 2: Initialize Database Migrations
Run database migrations prior to routing live ingress:
```bash
docker compose -f docker-compose.prod.yml run --rm api alembic upgrade head
```

### Step 3: Run Pre-Flight Restore & Dependency Verification
Verify the multi-tier dependency graph (database, evidence storage, KEK keyring, and Merkle tree state):
```bash
docker compose -f docker-compose.prod.yml run --rm api python scripts/restore_verify.py
```

### Step 4: Launch Production Services
```bash
docker compose -f docker-compose.prod.yml up -d
```

### Step 5: Post-Deployment Smoke Test
Verify system liveness and privacy headers:
```bash
curl -i http://localhost/api/v1/health
```
Verify that:
- HTTP status is `200 OK`
- `Content-Security-Policy` header is present
- `X-Frame-Options: DENY` header is present
- `X-Content-Type-Options: nosniff` header is present

---

## 5. Operational Procedures

### A. Performing a Disaster Recovery Backup & Drill
```bash
# Generate verified backup snapshot with cryptographic manifest
docker compose -f docker-compose.prod.yml exec api python scripts/recovery_drill.py
```

### B. Key Rotation (KEK Keyring)
1. Generate new 32-byte hex key for version `N+1`.
2. Update `PAYLOAD_KEK_KEYRING` JSON to include both version `N` and `N+1`.
3. Set `PAYLOAD_KEK_ACTIVE_VERSION=N+1`.
4. Trigger online re-wrap of existing case DEKs via Moderator API (`POST /api/v1/moderator/reports/{report_id}/rewrap-keys`).

### C. Emergency Seal & Unseal
- **Emergency Seal**:
  If server tampering, legal seizure, or an intrusion is detected, an administrator can immediately seal the system via `POST /api/v1/moderator/security/emergency-seal`.
  - Blocks moderator plaintext access
  - Blocks export downloads
  - Blocks key destruction & retention sweeps
  - Anonymous ingestion remains functional to preserve evidence
- **Emergency Unseal**:
  Requires administrator authentication and valid TOTP MFA proof via `POST /api/v1/moderator/security/emergency-unseal`.
