# WhistleDrop

WhistleDrop is a secure, privacy-first backend platform designed for anonymous whistleblowing, incident reporting, and secure two-way communication between whistleblowers and moderators.

---

## Architecture

WhistleDrop is built as an asynchronous Python backend adhering to clean architecture and separation of concerns:

```text
whistledrop/
├── .env.example              # Template for environment configuration & secrets
├── .gitignore                # Git ignore rules for virtual environments, secrets, caches
├── docker-compose.yml        # Development PostgreSQL database container
├── requirements.txt          # Reproducible, pinned Python dependencies
├── README.md                 # Architecture, privacy/security models, and setup guide
├── app/
│   ├── __init__.py           # Package marker with application version
│   ├── main.py               # FastAPI entrypoint, middleware, and route mounting
│   ├── core/
│   │   ├── __init__.py
│   │   └── config.py         # Type-safe settings, secret validation, environment logic
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
    ├── test_config.py        # Configuration, CORS, and secret validation tests
    └── test_health.py        # Health and root endpoint tests
```

- **Framework:** FastAPI utilizing ASGI for high-concurrency asynchronous I/O.
- **Data Validation & Settings:** Pydantic v2 and Pydantic Settings for strict runtime validation.
- **Database Architecture:** Standardized on async PostgreSQL via SQLAlchemy 2.0 and `asyncpg` driver to prevent event-loop blocking under high submission loads.
- **Environment Management:** Multi-tier environment awareness (`development` vs `production`).

---

## Privacy Model

WhistleDrop is designed around the core principle of **Zero-Knowledge Anonymity**:

1. **Decoupled Identity:** Reports are never associated with user accounts, names, email addresses, or identifying attributes.
2. **Metadata Stripping:** Client IP addresses, User-Agent strings, and tracking headers are explicitly excluded from database models and persistent logs.
3. **Case-Code Token Retrieval:** Submissions generate high-entropy, randomly generated case codes that act as bearer tokens. The server stores only cryptographic hashes of these tokens. Whistleblowers can check status and communicate without logging in or providing identifying proofs.
4. **No Third-Party Analytics:** The application does not embed external analytics, trackers, or third-party client telemetry.

---

## Security Model

Security controls are implemented with defense-in-depth:

1. **Cryptographic Domain Separation:**
   - `JWT_SECRET`: Dedicated secret exclusively for moderator authentication tokens.
   - `CASE_CODE_SECRET`: Dedicated secret exclusively used for case-code derivation and hashing.
   - *Strict Prohibition:* Configuration validation rejects setups that reuse the same secret across different security contexts.
2. **Production-Hardened Defaults:**
   - `DEBUG` is strictly enforced to `False` in production environments.
   - OpenAPI documentation endpoints (`/docs`, `/redoc`, `/openapi.json`) are disabled when `DEBUG=False` to prevent API schema reconnaissance.
   - Minimum entropy requirements (min 32 characters) and placeholder rejection are enforced for production secrets at application startup.
3. **Restrictive CORS:**
   - Permissive wildcard origins (`allow_origins=["*"]`) with credentials are prohibited.
   - Allowed origins are strictly configurable via `BACKEND_CORS_ORIGINS`.
   - In production, CORS defaults to an empty allowlist (enforcing strict browser Same-Origin Policy) unless explicit origins are configured.

---

## Threat Model

| Threat | Target / Impact | Mitigation Strategy |
| :--- | :--- | :--- |
| **Case-Code Enumeration / Brute Force** | Adversaries brute-forcing access to confidential reports. | High-entropy CSPRNG tokens, non-sequential codes, keyed HMAC/salted hashing (`CASE_CODE_SECRET`), and upcoming per-IP / global rate limiting. |
| **Traffic Correlation / Metadata Leakage** | Identifying a whistleblower by correlating submission timestamps or network metadata. | Strict exclusion of client IP/headers from application storage and logging; future support for Tor onion services. |
| **Cross-Domain Secret Compromise** | Compromise of moderator JWT secrets granting ability to forge or decrypt whistleblower case codes. | Cryptographic secret separation; `JWT_SECRET` and `CASE_CODE_SECRET` are independent and validated to never share keys. |
| **API Schema Reconnaissance** | Attackers scanning interactive API documentation to map out endpoints and attack vectors. | Automatic suppression of Swagger UI (`/docs`), ReDoc (`/redoc`), and OpenAPI schema (`/openapi.json`) when `DEBUG=False` in production. |
| **Unauthorized Moderator Access** | Malicious actors accessing case management portals. | Role-Based Access Control (RBAC), short-lived JWTs, and upcoming tamper-evident audit logging for all moderator actions. |

---

## Development Roadmap

- [x] **Phase 0:** Backend Foundation, Configuration & Health Check
- [x] **Phase 0.5:** Security Hardening (Cryptographic Secret Separation, Environment-Aware Debug, Restrictive CORS, Async DB Standardization)
- [ ] **Phase 1 (Planned):** Core Data Models & Asynchronous Database Migrations (SQLAlchemy + Alembic)
- [ ] **Phase 2 (Planned):** Secure Report Ingestion & Cryptographic Case-Code Generation
- [ ] **Phase 3 (Planned):** Case Tracking & Anonymous Two-Way Follow-up Channel
- [ ] **Phase 4 (Planned):** Moderator Authentication & Role-Based Access Control
- [ ] **Phase 5 (Planned):** Case Status Lifecycle Management & Immutable Audit Trail
- [ ] **Phase 6 (Planned):** Evidence Attachment Storage & Advanced Defense (Rate Limiting, ClamAV Scanning)

---

## Getting Started

### 1. Prerequisites

- Python 3.10+ (Python 3.13 tested)
- Docker & Docker Compose (optional for local database container)

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

### 4. Start Development Database (Docker)

If Docker is available:

```bash
docker compose up -d
```

### 5. Run Development Server

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 6. Run Tests

```bash
pytest -v
```
