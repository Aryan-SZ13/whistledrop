# WhistleDrop

A secure, privacy-first whistleblower and incident reporting backend platform.

---

## Overview

WhistleDrop provides a secure, auditable, and anonymous channel for submitting whistleblowing reports, tracking investigations, and communicating with moderators without compromising anonymity.

---

## Tech Stack (Phase 0 Foundation)

- **Language:** Python 3.13+
- **Framework:** FastAPI
- **Data Validation & Settings:** Pydantic v2 / Pydantic Settings
- **ASGI Server:** Uvicorn
- **Database (Development):** PostgreSQL 16 (via Docker Compose)
- **Testing:** Pytest & HTTPX / FastAPI TestClient

---

## Project Structure

```text
whistledrop/
├── .env.example              # Template for local environment variables
├── .gitignore                # Git ignore patterns
├── docker-compose.yml        # Development database container definition
├── requirements.txt          # Python dependencies
├── README.md                 # Project documentation and setup guide
├── app/
│   ├── __init__.py           # Application package marker with version
│   ├── main.py               # FastAPI application entrypoint
│   ├── core/
│   │   ├── __init__.py
│   │   └── config.py         # Application configuration & settings
│   └── api/
│       ├── __init__.py
│       └── v1/
│           ├── __init__.py
│           ├── api.py        # API router aggregator
│           └── endpoints/
│               ├── __init__.py
│               └── health.py # Health check endpoint
└── tests/
    ├── __init__.py
    └── test_health.py        # Foundation & health check tests
```

---

## Getting Started

### 1. Prerequisites

- Python 3.10+ (Python 3.13 recommended)
- Docker & Docker Compose (optional for local DB container)

### 2. Environment Setup

Clone the repository and set up a virtual environment:

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Copy the example environment file:

```bash
cp .env.example .env
```

### 4. Start Development Database (Docker)

If Docker is installed:

```bash
docker compose up -d
```

### 5. Run the Application

Start the local development server with hot-reload enabled:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Interactive documentation is available at:
- Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
- ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)
- Health check: [http://localhost:8000/health](http://localhost:8000/health) or [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)

### 6. Run Tests

Execute the test suite using pytest:

```bash
pytest
```

---

## Development Roadmap

- [x] **Phase 0:** Backend Foundation, Configuration & Health Check
- [ ] **Phase 1:** Core Data Models & Database Migrations
- [ ] **Phase 2:** Report Ingestion & Case-Code Generation
- [ ] **Phase 3:** Case Tracking & Anonymous Follow-up
- [ ] **Phase 4:** Moderator Authentication & Authorization
- [ ] **Phase 5:** Status Management & Audit Logging
- [ ] **Phase 6:** Evidence Uploads & Advanced Security
