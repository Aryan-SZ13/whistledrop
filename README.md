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
│   │   └── config.py         # Type-safe settings, secret validation, environment logic
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
│   └── api/
│       ├── __init__.py
│       └── v1/
│           ├── __init__.py
│           ├── api.py        # API router aggregator
│           └── endpoints/
│               ├── __init__.py
│               └── health.py # Health check probe endpoint
└── tests/
    ├── __init__.py
    ├── conftest.py           # Test database fixtures and async session setup
    ├── test_config.py        # Configuration, CORS, and secret validation tests
    ├── test_database.py      # Database models, constraints, enums, and schema tests
    └── test_health.py        # Health and root endpoint tests
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
3. **Case-Code Token Retrieval:** Submissions generate a high-entropy, cryptographically derived case code that acts as a bearer token. The database stores only a one-way cryptographic digest (`case_code_digest`). Whistleblowers use this case code to check status and read updates without creating accounts or revealing identity.

---

## Security Model

Security controls are implemented with defense-in-depth:

1. **Cryptographic Domain Separation:**
   - `JWT_SECRET`: Dedicated secret exclusively for signing and verifying moderator authentication tokens.
   - `CASE_CODE_SECRET`: Dedicated secret exclusively used for case-code derivation and one-way hashing.
   - *Strict Prohibition:* Configuration validation rejects setups that reuse the same secret across different security contexts.
2. **Impact of Secret Compromise:**
   - **`JWT_SECRET` compromise:** An attacker could forge moderator authorization tokens and impersonate moderators.
   - **`CASE_CODE_SECRET` compromise:** An attacker cannot "decrypt" stored one-way case-code digests (as cryptographic digests are inherently non-reversible), but an attacker with database read access could perform offline dictionary or brute-force precomputation attacks against suspected candidate case codes.
3. **Production-Hardened Defaults:**
   - `DEBUG` is strictly enforced to `False` in production environments.
   - OpenAPI documentation endpoints (`/docs`, `/redoc`, `/openapi.json`) are disabled when `DEBUG=False` to prevent API schema reconnaissance.
   - Minimum entropy requirements (min 32 characters) and placeholder rejection are enforced for production secrets at application startup.
4. **Restrictive CORS:**
   - Permissive wildcard origins (`allow_origins=["*"]`) are prohibited.
   - `allow_credentials` is set to `False` by default because authentication uses `Authorization: Bearer <token>` headers rather than browser cookies.
   - In production, CORS defaults to an empty allowlist (enforcing strict browser Same-Origin Policy) unless explicit origins are configured.

---

## Threat Model

| Threat | Target / Impact | Mitigation Strategy |
| :--- | :--- | :--- |
| **Case-Code Enumeration / Brute Force** | Adversaries guessing case codes to view confidential reports. | High-entropy CSPRNG tokens, non-sequential codes, keyed HMAC/salted one-way digests (`CASE_CODE_SECRET`), and upcoming per-IP / global rate limiting. |
| **Traffic Correlation / Metadata Leakage** | Correlating report submissions with network traffic or server logs. | Application models and application logs omit submitter identity and network metadata; infrastructure ingress proxies must be configured to discard or anonymize access logs. |
| **Cross-Domain Secret Compromise** | Compromise of moderator JWT secrets impacting report access. | Cryptographic secret separation; `JWT_SECRET` and `CASE_CODE_SECRET` are independent keys validated to never share values. |
| **API Schema Reconnaissance** | Attackers scanning interactive API documentation to map out endpoints and attack vectors. | Automatic suppression of Swagger UI (`/docs`), ReDoc (`/redoc`), and OpenAPI schema (`/openapi.json`) when `DEBUG=False` in production. |
| **Unauthorized Moderator Access** | Malicious actors accessing case management records. | Role-Based Access Control (RBAC), short-lived JWTs, and structured audit logs for all moderator actions. |

---

## Development Roadmap

- [x] **Phase 0:** Backend Foundation, Configuration & Health Check
- [x] **Phase 0.5:** Security Hardening (Cryptographic Secret Separation, Environment-Aware Debug, Restrictive CORS, Async DB Standardization)
- [x] **Phase 1:** Async Database Foundation (PostgreSQL, SQLAlchemy 2.0 Async, Enums, Models, Alembic Migrations)
- [x] **Phase 2:** Secure Anonymous Report Ingestion & Cryptographic Case-Code Generation
- [ ] **Phase 3 (Planned):** Case Tracking & Moderator Status Updates
- [ ] **Phase 4 (Planned):** Moderator Authentication & Role-Based Access Control (RBAC)
- [ ] **Phase 5 (Planned):** Case Status Lifecycle Management & Immutable Audit Trail
- [ ] **Phase 6 (Planned):** Evidence Attachment Storage & Advanced Defense (Rate Limiting, ClamAV Scanning)

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
