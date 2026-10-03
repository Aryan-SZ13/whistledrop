# WhistleDrop

WhistleDrop is a privacy-first backend platform designed for anonymous whistleblowing, incident reporting, and case tracking with moderator status updates.

---

## Architecture

WhistleDrop is structured as an asynchronous Python backend adhering to clean architecture, explicit dependency injection, and strict separation of concerns:

```text
whistledrop/
├── .env.example              # Template for environment configuration & secrets
├── .gitignore                # Git ignore rules for virtual environments, secrets, caches
├── alembic.ini               # Alembic database migration configuration
├── docker-compose.yml        # Development PostgreSQL database container
├── requirements.txt          # Reproducible, pinned Python dependencies
├── README.md                 # Architecture, privacy/security models, and setup guide
├── alembic/
│   ├── env.py                # Async migration runner linked to model metadata
│   ├── script.py.mako        # Migration template
│   └── versions/             # Versioned schema migrations
├── app/
│   ├── __init__.py           # Package marker with application version
│   ├── main.py               # FastAPI entrypoint, middleware, and route mounting
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py         # Type-safe settings, secret validation, environment logic
│   │   └── security.py       # Argon2id password hashing, JWT tokens, CSPRNG case-codes
│   ├── db/
│   │   ├── __init__.py
│   │   └── session.py        # Async engine, sessionmaker, and get_db dependency
│   ├── models/
│   │   ├── __init__.py       # Model exports
│   │   ├── base.py           # DeclarativeBase base model class
│   │   ├── enums.py          # Domain enums (ReportCategory, ReportStatus, ModeratorRole)
│   │   ├── moderator.py      # Moderator accounts and roles
│   │   ├── report.py         # Core whistleblower report schema
│   │   ├── report_update.py  # Moderator case status updates
│   │   └── audit_log.py      # Action audit logs
│   ├── schemas/
│   │   ├── __init__.py       # Pydantic schemas export
│   │   ├── auth.py           # Moderator login and token schemas
│   │   ├── moderator.py      # Moderator report listing and inspection schemas
│   │   └── report.py         # Public request and response schemas
│   ├── services/
│   │   ├── __init__.py       # Services export
│   │   ├── auth_service.py   # Moderator authentication, hashing, and token issuance
│   │   ├── moderator_service.py # Protected report querying, filtering, and inspection
│   │   └── report_service.py # Core business logic for report submission and tracking
│   └── api/
│       ├── __init__.py
│       ├── deps.py           # Authentication & role-based authorization dependencies
│       └── v1/
│           ├── __init__.py
│           ├── api.py        # API router aggregator
│           └── endpoints/
│               ├── __init__.py
│               ├── auth.py   # Moderator authentication endpoints
│               ├── health.py # Health check probe endpoint
│               ├── moderator.py # Protected moderator report management routes
│               └── reports.py# Anonymous report submission & tracking endpoints
└── tests/
    ├── __init__.py
    ├── conftest.py           # Test database fixtures, isolation, and async session setup
    ├── test_auth.py          # Argon2id, JWT lifecycle, RBAC, and login tests
    ├── test_config.py        # Configuration, CORS, and secret validation tests
    ├── test_database.py      # Database models, constraints, enums, and schema tests
    ├── test_health.py        # Health and root endpoint tests
    ├── test_moderator.py     # Protected moderator control plane tests
    ├── test_reports.py       # Report creation, validation, and crypto regression tests
    └── test_tracking.py      # Public case tracking, isolation, and minimization tests
```

- **Framework:** FastAPI utilizing ASGI for high-concurrency asynchronous I/O.
- **Data Validation & Settings:** Pydantic v2 and Pydantic Settings for strict runtime validation.
- **Database Architecture:** Standardized on async PostgreSQL via SQLAlchemy 2.0 async engine and `asyncpg` driver. Schema creation and evolution is strictly managed via Alembic migrations (no `Base.metadata.create_all()` in production).
- **Environment Management:** Multi-tier environment awareness (`development` vs `production`).

---

## Privacy Model

WhistleDrop is built around **privacy-first anonymous reporting**:

1. **Decoupled Identity:** The application data model does not store reporter identity. Database schemas explicitly contain no columns for names, email addresses, phone numbers, account IDs, or submitter identifiers.
2. **Application-Level Metadata Exclusion:** The application database models and application logs do not persist submitter IP addresses or User-Agent headers. (Note: infrastructure-level logging at reverse proxies, load balancers, or hosting providers depends on deployment configuration and must be hardened independently in production environments).
3. **Case-Code Token Retrieval:** Submissions generate a high-entropy case code using a cryptographically secure pseudo-random number generator (CSPRNG). The server derives an HMAC-SHA256 one-way digest (`case_code_digest`) using `CASE_CODE_SECRET` for database storage. The usable plaintext case code is returned to the user only once and never stored in PostgreSQL or application logs. Whistleblowers use this case code to check status and read updates without creating accounts or revealing identity.
4. **Application-Collected Identity vs. Voluntary Content Disclosure:**
   - *Application-collected identity:* The application architecture strictly eliminates tracking, account association, IP storage, and client fingerprinting.
   - *Voluntarily embedded content:* The platform cannot prevent reporters from voluntarily embedding identifying details within free-text report descriptions or metadata URLs (e.g., mentioning names, specific roles, or submitting URLs containing identifying usernames). Reporters should exercise caution regarding the text and external links they provide.
5. **Timestamp Precision Tradeoff:**
   - The report creation response includes the exact timezone-aware `created_at` timestamp. This is a deliberate current design choice to provide immediate confirmation and tracking fidelity. Future privacy hardening passes may evaluate timestamp coarse-graining (quantizing submission times to hour or day boundaries) to mitigate potential network traffic-correlation attacks.

---

## Security Model

Security controls are implemented with defense-in-depth:

1. **Cryptographic Domain Separation:**
   - `JWT_SECRET`: Dedicated secret exclusively for signing and verifying moderator authentication tokens.
   - `CASE_CODE_SECRET`: Dedicated secret exclusively used to derive HMAC digests from case codes.
   - *Strict Prohibition:* Configuration validation rejects setups that reuse the same secret across different security contexts.
2. **Impact of Secret Compromise:**
   - **`JWT_SECRET` compromise:** An attacker could forge moderator authorization tokens and impersonate moderators.
   - **`CASE_CODE_SECRET` compromise:** An attacker cannot "decrypt" stored one-way case-code digests (as cryptographic digests are inherently non-reversible), but an attacker with database read access could perform offline dictionary or brute-force precomputation attacks against suspected candidate case codes.
3. **Authentication vs. Anonymous Reporting Boundary:**
   - *Whistleblowers:* Never register, provide credentials, or establish sessions. Access to case tracking is authenticated purely via bearer case-code possession.
   - *Moderators / Admins:* Internal personnel undergo credential authentication (`POST /api/v1/auth/login`) to receive short-lived bearer JWTs for role-gated administration.
4. **Moderator Password Hashing, Canonicalization & Timing-Attack Mitigation:**
   - Password hashing uses **Argon2id** (`argon2-cffi`). The configuration (`time_cost=3`, `memory_cost=65536` [64 MiB], `parallelism=4`, `hash_len=32`, `salt_len=16`) is intentionally above OWASP's current minimum Argon2id baseline and was chosen as an engineering tradeoff between memory hardness and authentication latency.
   - Username canonicalization prevents casing and surrounding-whitespace ambiguity. It is not a Unicode confusable/homograph defense.
   - Failed authentication yields a uniform `401 Unauthorized` (`"Incorrect username or password"`) without revealing whether the username exists or the password was incorrect.
   - *Timing Side-Channel Mitigation:* Authentication attempts perform password-hash verification for both existing and nonexistent usernames to reduce obvious response-time differences that could otherwise aid username enumeration. This does not provide a formal constant-time guarantee across the full network stack.

5. **Context-Bound Short-Lived JWT Bearer Tokens:**
   - Issued upon successful moderator authentication with a 30-minute expiration (`ACCESS_TOKEN_EXPIRE_MINUTES=30`).
   - Signed using `HS256` with `JWT_SECRET`. Algorithm confusion is strictly prevented by specifying the allowed algorithm list during token decoding.
   - Context binding: Every token includes explicit `iss` (`JWT_ISSUER`) and `aud` (`JWT_AUDIENCE`) claims, strictly verified upon decoding.
   - *Role Source of Truth:* The database `Moderator.role` is the authoritative source for authorization; `role` is intentionally excluded from the JWT payload, preventing token-level privilege escalation.
   - Payload strictly contains: `sub`, `iat`, `exp`, `iss`, `aud`. Plaintext passwords, password hashes, secrets, case codes, report data, and PII are strictly excluded.
6. **Moderator Account Lifecycle & Inactive Account Enforcement:**
   - The `Moderator` model includes an `is_active` boolean field (default: `True`).
   - Authentication flow enforces: JWT signature/claims validation → load moderator from DB → check `is_active` → authorize moderator.
   - Deactivated moderators (`is_active=False`) are rejected during both login and token validation with a generic `401 Unauthorized` response (`"Could not validate credentials"`).
   - Account deactivation is non-destructive, preserving historical associations with audit logs and report updates without requiring user deletion.
7. **Role-Based Access Control (RBAC):**
   - Tiered authorization dependencies enforce least privilege using database records as the source of truth:
     - `require_moderator`: Permits authorized `MODERATOR` and `ADMIN` personnel to perform triage operations.
     - `require_admin`: Strictly limits privileged configurations and admin actions to `ADMIN` accounts.
8. **Protected Moderator Control Plane & Least-Privilege Representation:**
   - Internal management endpoints (`GET /api/v1/moderator/reports`, `GET /api/v1/moderator/reports/{report_id}`) require `Depends(require_moderator)`, gating access strictly to authorized personnel (`MODERATOR` or `ADMIN`).
   - Querying supports filtering by `status` and `category`, deterministic ordering (`created_at.desc(), id.desc()`), and safe bounded pagination (`limit` capped at 100, `offset >= 0`).
   - Privileged response schemas (`ModeratorReportResponse`, `ModeratorReportListResponse`) expose internal report UUIDs, timestamps, category, description, and evidence URL metadata to facilitate triage.
   - *Privacy Isolation:* The bearer `case_code_digest`, plaintext case codes, reporter identity, and internal audit logs are strictly omitted from moderator response schemas, preserving anonymous reporter boundaries even against privileged operators.
9. **Internal ID Concealment & Public Data Minimization:**
   - Internal database primary keys (UUIDs) remain strictly internal and are never exposed in public endpoints.
   - Public report ingestion response schema (`POST /api/v1/reports`):
     ```json
     {
       "case_code": "wdc_...",
       "status": "SUBMITTED",
       "created_at": "2026-10-03T16:20:00Z"
     }
     ```
   - Public report tracking response schema (`GET /api/v1/reports/{case_code}`):
     ```json
     {
       "status": "UNDER_REVIEW",
       "updates": [
         {
           "message": "Initial assessment opened by security team.",
           "created_at": "2026-10-03T16:30:00Z"
         }
       ]
     }
     ```
     *Strict Omission:* Internal UUIDs, case_code_digest, description, evidence_url, audit logs, and moderator identities are completely excluded from public tracking.
10. **Metadata-Only Evidence Handling:**
    - Submitted `evidence_url` values are strictly validated via structured URL parsers and stored purely as text metadata. The server never makes outbound HTTP requests or fetches submitted URLs, eliminating Server-Side Request Forgery (SSRF) risks.
11. **Production-Hardened Defaults:**
    - `DEBUG` is strictly enforced to `False` in production environments.
    - OpenAPI documentation endpoints (`/docs`, `/redoc`, `/openapi.json`) are disabled when `DEBUG=False` to prevent API schema reconnaissance.
    - Minimum entropy requirements (min 32 characters) and placeholder rejection are enforced for production secrets at application startup.
12. **Restrictive CORS:**
    - Permissive wildcard origins (`allow_origins=["*"]`) are prohibited.
    - `allow_credentials` is set to `False` by default because authentication uses `Authorization: Bearer <token>` headers rather than browser cookies.
    - In production, CORS defaults to an empty allowlist (enforcing strict browser Same-Origin Policy) unless explicit origins are configured.
13. **Case Lifecycle State Machine, Public/Internal Update Separation & Auditing:**
    - *Lifecycle State Machine:* Report status transitions are strictly governed by an explicit domain state machine (`SUBMITTED -> UNDER_REVIEW -> RESOLVED | DISMISSED`). Illegal transitions are rejected with HTTP 409 Conflict.
    - *Concurrency & Atomic Mutations:* Transitions and update posts utilize row-level locking (`SELECT ... FOR UPDATE`) and atomic transactional persistence, ensuring report updates, status mutations, and audit records commit together or roll back completely.
    - *Visibility Separation:* Updates to reports are categorized as either `PUBLIC_UPDATE` (visible to the anonymous reporter in case tracking) or `INTERNAL_NOTE` (strictly accessible only via authorized moderator endpoints).
    - *Append-Only Audit Trail:* All moderation actions generate structured `AuditLog` records containing controlled metadata (e.g. `from_status`, `to_status`, `update_type`). Passwords, JWTs, case codes, and free-text notes are never stored in audit metadata. (Note: Current audit logs are append-only at the application level; cryptographic tamper-evidence is reserved for future phases).

---

## Threat Model

| Threat | Target / Impact | Mitigation Strategy |
| :--- | :--- | :--- |
| **Case-Code Enumeration / Brute Force** | Adversaries guessing case codes to view confidential reports. | High-entropy CSPRNG tokens, non-sequential codes, keyed HMAC/salted one-way digests (`CASE_CODE_SECRET`), and upcoming per-IP / global rate limiting. |
| **Traffic Correlation / Metadata Leakage** | Correlating report submissions with network traffic or server logs. | Application models and application logs omit submitter identity and network metadata; infrastructure ingress proxies must be configured to discard or anonymize access logs. |
| **Cross-Domain Secret Compromise** | Compromise of moderator JWT secrets impacting report access. | Cryptographic secret separation; `JWT_SECRET` and `CASE_CODE_SECRET` are independent keys validated to never share values. |
| **API Schema Reconnaissance** | Attackers scanning interactive API documentation to map out endpoints and attack vectors. | Automatic suppression of Swagger UI (`/docs`), ReDoc (`/redoc`), and OpenAPI schema (`/openapi.json`) when `DEBUG=False` in production. |
| **Unauthorized Moderator Access** | Malicious actors accessing case management records. | Argon2id password hashing, canonical username normalization, active account verification (`is_active`), Role-Based Access Control (RBAC), context-bound JWTs, and structured audit logs. |

---

## Development Roadmap

- [x] **Phase 0:** Backend Foundation, Configuration & Health Check
- [x] **Phase 0.5:** Security Hardening (Cryptographic Secret Separation, Environment-Aware Debug, Restrictive CORS, Async DB Standardization)
- [x] **Phase 1:** Async Database Foundation (PostgreSQL, SQLAlchemy 2.0 Async, Enums, Models, Alembic Migrations)
- [x] **Phase 2:** Secure Anonymous Report Ingestion & Cryptographic Case-Code Generation
- [x] **Phase 3:** Public Anonymous Case Tracking & Status Updates
- [x] **Phase 4:** Moderator Authentication & Role-Based Access Control (RBAC)
- [x] **Phase 4.1:** Authentication Lifecycle Hardening (Account Lifecycle `is_active`, Context-Bound JWTs, DB Role Authority, Test Endpoint Removal)
- [x] **Phase 4.2:** Authentication Enumeration & Timing Hardening (Fixed Dummy Argon2id Verification)
- [x] **Phase 5:** Protected Moderator Control Plane (Report Listing, Filtering, Bounded Pagination, and Detail Inspection)
- [x] **Phase 5.1:** Moderator Query Least-Privilege Hardening (Explicit SQL Column Projections)
- [x] **Phase 6:** Case Lifecycle State Machine, Public/Internal Update Separation, and Auditing
- [ ] **Phase 7 (Planned):** Evidence Attachment Storage & Advanced Defense (Rate Limiting, ClamAV Scanning)





---

## Getting Started

### 1. Prerequisites

- Python 3.10+ (Python 3.13 tested)
- PostgreSQL 16 (local installation or via Docker Compose)

### 2. Environment Setup

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Install reproducible dependencies
pip install -r requirements.txt
```

### 3. Configuration

```bash
cp .env.example .env
```

Review and adjust variables in `.env` as needed for your development setup.

### 4. Database & Migrations

Start the development database:

```bash
docker compose up -d
```

Apply database migrations:

```bash
alembic upgrade head
```

### 5. Run Development Server

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 6. Run Tests

```bash
pytest -v
```
