# WhistleDrop — Requirements Traceability Matrix (RTM)
## Google Developer Groups on Campus SRM — Recruitment 2026–27

**System Title:** WhistleDrop — *Speak Without Being Seen*  
**Repository:** [https://github.com/Aryan-SZ13/whistledrop](https://github.com/Aryan-SZ13/whistledrop)  
**Evaluation Standard:** Demonstrable engineering quality, architectural rigor, and verifiable security controls.

---

## 1. Compliance Status Legend

- **VERIFIED**: Directly demonstrated by implementation, validated through automated regression and security tests with exit code 0.
- **PARTIALLY VERIFIED**: Behavior implemented, but certain external or manual interactions have residual boundary assumptions.
- **MISSING**: Requirement is not implemented in the current codebase.
- **BLOCKED**: Verification cannot be executed in the local host environment due to platform or daemon unavailability (e.g. Docker daemon).

---

## 2. Mandatory Core Requirements (Stage 1)

### A. Anonymous Reporting — REQUIRED

| Requirement Detail | Status | Implementation Source Files | API Route | Automated Test Reference | Verification Command & Result | Limitations & Context |
| :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| **No Registration / Auth** | **VERIFIED** | `app/api/v1/endpoints/reports.py`<br>`app/services/report_service.py` | `POST /api/v1/reports` | `tests/test_reports.py::test_submit_report_success_response_shape` | `pytest tests/test_reports.py` (Exit 0) | No cookies, IP, or user identity collected or stored. |
| **Allowed Categories** | **VERIFIED** | `app/models/enums.py`<br>`app/schemas/report.py` | `POST /api/v1/reports` | `tests/test_reports.py::test_submit_report_invalid_category` | `pytest tests/test_reports.py` (Exit 0) | Strict enum: `SECURITY`, `HARASSMENT`, `CORRUPTION`, `TECHNICAL`, `OTHER`. Extra or malformed values return HTTP 422. |
| **Description Validation** | **VERIFIED** | `app/schemas/report.py` | `POST /api/v1/reports` | `tests/test_reports.py::test_submit_report_description_too_short` | `pytest tests/test_reports.py` (Exit 0) | Required. Min length 10 characters, max 10,000 characters. Trimmed before validation. |
| **Evidence URL Validation** | **VERIFIED** | `app/schemas/report.py` | `POST /api/v1/reports` | `tests/test_reports.py::test_submit_report_invalid_evidence_url` | `pytest tests/test_reports.py` (Exit 0) | Optional. Scheme restricted to `http` or `https`. SSRF/file schemes (`file://`, `ftp://`, `javascript:`) rejected. |
| **Malformed Payload Handling** | **VERIFIED** | `app/api/v1/endpoints/reports.py`<br>`app/schemas/report.py` | `POST /api/v1/reports` | `tests/test_reports.py::test_submit_report_forbids_extra_fields` | `pytest tests/test_reports.py` (Exit 0) | Pydantic `extra = "forbid"` blocks mass assignment and unexpected parameters with HTTP 422. |
| **Cryptographic Case Code** | **VERIFIED** | `app/core/security.py`<br>`app/services/report_service.py` | `POST /api/v1/reports` | `tests/test_reports.py::test_crypto_multiple_generated_case_codes_are_distinct` | `pytest tests/test_reports.py` (Exit 0) | Generated using `secrets.token_urlsafe(32)`. Unpredictable 256-bit CSPRNG entropy. |
| **Returned to Reporter** | **VERIFIED** | `app/schemas/report.py`<br>`app/services/report_service.py` | `POST /api/v1/reports` | `tests/test_reports.py::test_submit_report_success_response_shape` | `pytest tests/test_reports.py` (Exit 0) | Plaintext code returned strictly once in creation response `ReportCreateResponse.case_code`. |
| **Data Minimization in Response** | **VERIFIED** | `app/schemas/report.py` | `POST /api/v1/reports` | `tests/test_reports.py::test_plaintext_case_code_absent_from_database` | `pytest tests/test_reports.py` (Exit 0) | Response returns `status`, `category`, `created_at`, `case_code`. No database IDs, internal notes, or moderator details exposed. |

---

### B. Case-Code Security and Tracking — REQUIRED

| Requirement Detail | Status | Implementation Source Files | API Route | Automated Test Reference | Verification Command & Result | Limitations & Context |
| :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| **High-Entropy Generation** | **VERIFIED** | `app/core/security.py` | N/A (Utility) | `tests/test_reports.py::test_crypto_multiple_generated_case_codes_are_distinct` | `pytest tests/test_reports.py` (Exit 0) | `secrets.token_urlsafe(32)` yields 43+ characters with 256 bits of cryptographic entropy. |
| **HMAC Digest Storage** | **VERIFIED** | `app/core/security.py`<br>`app/models/report.py` | N/A (Storage) | `tests/test_reports.py::test_plaintext_case_code_absent_from_database` | `pytest tests/test_reports.py` (Exit 0) | Database stores only HMAC-SHA256(`CASE_CODE_SECRET`, `case_code`). Plaintext code is never persisted. |
| **Public Tracking Isolation** | **VERIFIED** | `app/services/report_service.py`<br>`app/api/v1/endpoints/reports.py` | `POST /api/v1/reports/track`<br>`GET /api/v1/reports/{case_code}` | `tests/test_tracking.py::test_tracking_valid_case_code_empty_updates` | `pytest tests/test_tracking.py` (Exit 0) | Authorizes access only to public status and public updates for the matched report. |
| **Invalid/Malformed Code Safety** | **VERIFIED** | `app/api/v1/endpoints/reports.py` | `POST /api/v1/reports/track` | `tests/test_tracking.py::test_tracking_invalid_case_code_not_found`<br>`test_tracking_malformed_case_code_rejected` | `pytest tests/test_tracking.py` (Exit 0) | Malformed length (< 16 or > 128 chars) returns HTTP 422. Unknown code returns generic HTTP 404. |
| **No Identity Disclosure** | **VERIFIED** | `app/services/report_service.py` | `POST /api/v1/reports/track` | `tests/test_tracking.py::test_tracking_public_data_minimization_regression` | `pytest tests/test_tracking.py` (Exit 0) | Reporter tracks without cookies, session tokens, or accounts. |
| **URL / Telemetry Leakage Elimination** | **VERIFIED** | `frontend/src/api/reports.ts`<br>`frontend/src/pages/TrackCasePage.tsx`<br>`app/api/v1/endpoints/reports.py` | `POST /api/v1/reports/track` | `frontend/src/__tests__/browser_network_audit.test.tsx`<br>`tests/test_tracking.py::test_tracking_never_logs_case_code_or_digest` | `npm --prefix frontend test`<br>`pytest tests/test_tracking.py` (Exit 0) | Frontend submits case code via HTTP request body (`POST /track`), eliminating case code from browser address bar, referrer headers, and server URL access logs. |
| **Moderator Interface Isolation** | **VERIFIED** | `app/schemas/moderator.py`<br>`app/services/moderator_service.py` | `GET /api/v1/moderator/reports` | `tests/test_moderator.py::test_moderator_cannot_view_case_code_digest` | `pytest tests/test_moderator.py` (Exit 0) | Moderators never see `case_code` or `case_code_digest`. |
| **Lookup Rate Limiting & Safeguards** | **VERIFIED** | `app/services/rate_limiter.py`<br>`app/api/v1/endpoints/reports.py` | `POST /api/v1/reports/track` | `tests/test_rate_limiting.py::test_lookup_never_creates_case_code_derived_redis_keys`<br>`test_lookup_global_safeguard_triggers_under_distributed_probing` | `pytest tests/test_rate_limiting.py` (Exit 0) | Redis rate limits by client IP and global window. Redis keys never contain plaintext or hashed case code. |

---

### C. Report Status and Updates — REQUIRED

| Requirement Detail | Status | Implementation Source Files | API Route | Automated Test Reference | Verification Command & Result | Limitations & Context |
| :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| **Initial Status** | **VERIFIED** | `app/models/enums.py`<br>`app/services/report_service.py` | `POST /api/v1/reports` | `tests/test_reports.py::test_submit_report_success_response_shape` | `pytest tests/test_reports.py` (Exit 0) | Default initial status is strictly `SUBMITTED`. |
| **Moderator Status Updates** | **VERIFIED** | `app/services/moderator_service.py`<br>`app/api/v1/endpoints/moderator.py` | `PATCH /api/v1/moderator/reports/{id}/status` | `tests/test_moderator.py::test_update_report_status_valid_transition` | `pytest tests/test_moderator.py` (Exit 0) | Requires authenticated `MODERATOR` or `ADMIN` role. |
| **Enforced State Machine** | **VERIFIED** | `app/services/moderator_service.py` | `PATCH /api/v1/moderator/reports/{id}/status` | `tests/test_moderator.py::test_update_report_status_invalid_transition` | `pytest tests/test_moderator.py` (Exit 0) | `SUBMITTED → UNDER_REVIEW → RESOLVED / DISMISSED`. Direct jumps or invalid moves return HTTP 400. |
| **Terminal Case Reopening Rule** | **VERIFIED** | `app/services/moderator_service.py` | `PATCH /api/v1/moderator/reports/{id}/status` | `tests/test_moderator.py::test_reopen_report_admin_only`<br>`test_reopen_report_requires_reason` | `pytest tests/test_moderator.py` (Exit 0) | `RESOLVED` and `DISMISSED` are terminal. Can only be reopened to `UNDER_REVIEW` by `ADMIN` with minimum 10-char reason (plus Quorum if enabled). |
| **Public Updates Attachment** | **VERIFIED** | `app/services/moderator_service.py` | `POST /api/v1/moderator/reports/{id}/updates` | `tests/test_moderator.py::test_add_public_update` | `pytest tests/test_moderator.py` (Exit 0) | Moderators can post `PUBLIC_UPDATE` (visible to reporter) or `INTERNAL_NOTE` (moderator-only). |
| **Reporter Visibility of Updates** | **VERIFIED** | `app/services/report_service.py` | `POST /api/v1/reports/track` | `tests/test_tracking.py::test_tracking_with_chronological_updates` | `pytest tests/test_tracking.py` (Exit 0) | Reporter retrieves chronological list of `PUBLIC_UPDATE` items with ISO 8601 timestamps. |
| **Internal Notes Confidentiality** | **VERIFIED** | `app/services/report_service.py` | `POST /api/v1/reports/track` | `tests/test_moderator.py::test_public_tracking_excludes_internal_notes` | `pytest tests/test_moderator.py` (Exit 0) | `INTERNAL_NOTE` items are strictly filtered out of the public tracking query. |
| **Least-Privilege Query Projection** | **VERIFIED** | `app/services/report_service.py` | `POST /api/v1/reports/track` | `tests/test_moderator.py::test_public_tracking_updates_query_column_least_privilege` | `pytest tests/test_moderator.py` (Exit 0) | Tracking query selects only `message` and `created_at`. Does not query `id`, `created_by`, or `type`. |
| **Optimistic Concurrency Control** | **VERIFIED** | `app/models/report.py`<br>`app/services/moderator_service.py` | `PATCH /api/v1/moderator/reports/{id}/status` | `tests/test_moderator.py::test_concurrent_status_update_version_conflict` | `pytest tests/test_moderator.py` (Exit 0) | Uses integer `version` counter. Stale update attempts fail with HTTP 409 Conflict. |

---

### D. Moderator Authentication and Authorization — REQUIRED

| Requirement Detail | Status | Implementation Source Files | API Route | Automated Test Reference | Verification Command & Result | Limitations & Context |
| :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| **Authenticated Access** | **VERIFIED** | `app/core/security.py`<br>`app/api/deps.py` | `/api/v1/moderator/*` | `tests/test_auth.py::test_login_success_and_jwt_issuance`<br>`test_unauthenticated_moderator_request_fails` | `pytest tests/test_auth.py` (Exit 0) | Argon2id password hashing + JWT Bearer token authentication. |
| **Role-Based Access Control** | **VERIFIED** | `app/api/deps.py`<br>`app/models/enums.py` | `/api/v1/moderator/*` | `tests/test_auth.py::test_moderator_cannot_access_admin_endpoints` | `pytest tests/test_auth.py` (Exit 0) | Two tiers: `MODERATOR` (triage/updates) and `ADMIN` (reopening, canary, unsealing, sessions). |
| **Session Lifecycle & Invalidation** | **VERIFIED** | `app/services/session_service.py`<br>`app/models/session.py` | `POST /api/v1/moderator/auth/logout`<br>`POST /api/v1/moderator/auth/refresh` | `tests/test_auth.py::test_logout_revokes_session`<br>`test_refresh_token_flow` | `pytest tests/test_auth.py` (Exit 0) | Server-side `moderator_sessions` table with SHA-256 token hashing and instant revocation. |
| **MFA / TOTP Security** | **VERIFIED** | `app/services/mfa_service.py`<br>`app/api/v1/endpoints/moderator.py` | `POST /api/v1/moderator/mfa/enroll`<br>`POST /api/v1/moderator/mfa/verify` | `tests/test_phase_18_19_20.py::test_dead_man_switch_check_in_with_totp` | `pytest tests/test_phase_18_19_20.py` (Exit 0) | RFC 6238 TOTP with AES-256-GCM encrypted secret storage (`MFA_KEK_SECRET`). |
| **Reporter Isolation from Moderator APIs** | **VERIFIED** | `app/api/deps.py` | `/api/v1/moderator/*` | `tests/test_auth.py::test_public_user_cannot_invoke_moderator_api` | `pytest tests/test_auth.py` (Exit 0) | Missing or invalid Bearer token returns HTTP 401 Unauthorized. |

---

### E. Privacy and Application Security — REQUIRED

| Requirement Detail | Status | Implementation Source Files | API Route | Automated Test Reference | Verification Command & Result | Limitations & Context |
| :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| **Zero Identity Collection** | **VERIFIED** | `app/models/report.py`<br>`app/services/report_service.py` | `POST /api/v1/reports` | `tests/test_rate_limiting.py::test_privacy_no_identity_stored_in_postgres` | `pytest tests/test_rate_limiting.py` (Exit 0) | No columns for email, name, IP, or user-agent in reports schema. |
| **No Client Header Logging** | **VERIFIED** | `deploy/nginx/nginx.conf`<br>`app/main.py` | All Routes | `tests/test_tracking.py::test_tracking_never_logs_case_code_or_digest` | Manual config audit & `pytest tests/test_tracking.py` (Exit 0) | Nginx `log_format anonymous` strips IP, User-Agent, and Referer headers. |
| **Error Handling / Trace Redaction** | **VERIFIED** | `app/main.py`<br>`app/core/errors.py` | All Routes | `tests/test_tracking.py::test_tracking_database_error_safety` | `pytest tests/test_tracking.py` (Exit 0) | Database exceptions return sanitized generic error messages (`detail="Database operation failed"`). |
| **Rate Limiting (Fail-Closed)** | **VERIFIED** | `app/services/rate_limiter.py` | All Routes | `tests/test_rate_limiting.py::test_redis_outage_fails_closed_on_submission`<br>`test_redis_outage_fails_closed_on_lookup` | `pytest tests/test_rate_limiting.py` (Exit 0) | Redis-backed sliding-window rate limiter fails closed if Redis becomes unavailable. |
| **Reverse-Proxy Trust Boundary** | **VERIFIED** | `Dockerfile`<br>`docker-compose.prod.yml`<br>`app/core/config.py` | Ingress | `tests/test_rate_limiting.py::test_proxy_trust_pinned_nginx_ip_rejects_other_internal_containers` | `pytest tests/test_rate_limiting.py` (Exit 0) | Uvicorn `--forwarded-allow-ips` and application `TRUSTED_PROXY_CIDRS` restricted strictly to `127.0.0.1,172.28.0.10/32`. |
| **Confidential Cache Control** | **VERIFIED** | `app/api/v1/endpoints/reports.py`<br>`app/api/v1/endpoints/canary.py` | Sensitive Routes | `tests/test_tracking.py::test_tracking_valid_case_code_empty_updates` | `pytest tests/test_tracking.py` (Exit 0) | `Cache-Control: no-store, no-cache, must-revalidate, private`, `Pragma: no-cache` on all sensitive responses. |

---

### F. API Behavior — REQUIRED

| Requirement Detail | Status | Implementation Source Files | API Route | Automated Test Reference | Verification Command & Result | Limitations & Context |
| :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| **Meaningful HTTP Status Codes** | **VERIFIED** | `app/api/v1/endpoints/*` | All Routes | Full pytest suite (343 tests) | `pytest tests/ -v` (Exit 0) | 200 OK, 201 Created, 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found, 409 Conflict, 422 Unprocessable Content, 429 Too Many Requests. |
| **Consistent Error Schema** | **VERIFIED** | `app/schemas/common.py`<br>`app/main.py` | All Routes | Full pytest suite | `pytest tests/ -v` (Exit 0) | Standard `{"detail": "..."}` or structured validation errors. |
| **Interactive OpenAPI / Swagger** | **VERIFIED** | `app/main.py` | `/docs`<br>`/redoc`<br>`/api/v1/openapi.json` | Manual inspection & endpoint routing | `uvicorn app.main:app` (Mounts OpenAPI schemas) | Configurable via settings. Available in non-production or when explicitly enabled. |

---

## 3. Optional Enhancements & Bonus Features (Stage 2)

| Optional Enhancement | Status | Implementation Details | Source Files & Routes | Test Reference | User Documentation |
| :--- | :---: | :--- | :--- | :--- | :--- |
| **Moderator / Admin Dashboard** | **VERIFIED** | React SPA with dedicated case queue, status triage, update posting, internal notes, audit log inspection, and security controls. | `frontend/src/pages/ModeratorDashboardPage.tsx`<br>`frontend/src/pages/ModeratorCaseDetailPage.tsx` | `frontend/src/__tests__/components.test.tsx` (Exit 0) | Documented in `README.md` and `frontend/README.md`. |
| **Permanent Case Closure** | **VERIFIED** | Strict terminal state machine (`RESOLVED`/`DISMISSED`). Cannot be transitioned except through administrator-only reason-bound action (or Quorum). | `app/services/moderator_service.py` | `tests/test_moderator.py::test_update_report_status_invalid_transition` | Documented in `README.md` (State Machine section). |
| **Additional Privacy Protections** | **VERIFIED** | HMAC-SHA256 case-code digests, no IP logging, referer stripping, memory-only case tracking in frontend, fail-closed rate limiting. | `app/core/security.py`<br>`deploy/nginx/nginx.conf` | `tests/test_rate_limiting.py`<br>`frontend/src/__tests__/security.test.tsx` | Documented in `SECURITY.md` and `THREAT_MODEL.md`. |
| **Evidence / File Upload** | **VERIFIED** | Multipart file upload with MIME magic sniffing, ClamAV streaming antivirus scan, quarantine storage, promotion, and AES-256-GCM encryption. | `app/services/evidence_service.py`<br>`app/api/v1/endpoints/evidence.py` | `tests/test_evidence.py` (23 tests passing) | Documented in `README.md` (Phase 8 Architecture). |
| **Search and Advanced Filtering** | **VERIFIED** | Moderator case listing supports category filter, status filter, priority filter, date range, assignment filter, and sanitized text search. | `app/services/moderator_service.py`<br>`app/api/v1/endpoints/moderator.py` | `tests/test_moderator.py::test_filter_reports_by_category_and_status` | Documented in API endpoint table in `README.md`. |
| **Swagger / OpenAPI Documentation** | **VERIFIED** | Comprehensive OpenAPI schema with route tags, field descriptions, response models, and security schemes. | `app/main.py` | Root router mount `/docs` | Documented in `README.md`. |
| **Automated Tests** | **VERIFIED** | 343 pytest backend tests + 14 vitest frontend tests + 5-tier cryptographic recovery simulation. | `tests/`<br>`frontend/src/__tests__/` | Pytest and Vitest test suites (All green, exit code 0) | Documented in `README.md` with exact reproduction commands. |
| **Containerized Deployment Configuration** | **PARTIALLY VERIFIED / BLOCKED** | Hardened multi-stage Dockerfile, docker-compose.prod.yml with least-privilege non-root users, healthchecks, resource limits, and Nginx reverse proxy. | `Dockerfile`<br>`docker-compose.prod.yml`<br>`deploy/nginx/nginx.conf` | Local configuration verified clean. Live multi-container startup **BLOCKED — NOT VERIFIED** (Docker daemon not installed). | Documented in `DEPLOYMENT.md`. |

---

## 4. Beyond-the-Brief Feature Inventory (Stage 3)

| Feature Subsystem | Implementation Location | Operational Mechanism | Test Reference | Boundary / Known Limitation |
| :--- | :--- | :--- | :--- | :--- |
| **Application-Level Payload Encryption (ALEE)** | `app/services/payload_encryption_service.py` | Envelope encryption using 256-bit AES-GCM. Unique Data Encryption Key (DEK) per report, encrypted under Key Encryption Key (KEK). AAD bound to `(report_id, object_type, object_id, field_name, aad_version)`. | `tests/test_phase_18_19_20.py::test_alee_report_submission_encrypts_payload`<br>`test_alee_aad_mismatch_fails_decryption` | Encryption occurs at application layer before database commit. Server memory briefly holds plaintext during active processing. |
| **Unified Cryptographic Erasure** | `app/services/payload_encryption_service.py`<br>`app/services/retention_service.py` | Zeroizes and transactionally deletes case DEK upon report withdrawal. Decrypting old ciphertexts becomes mathematically impossible. | `tests/test_phase_18_19_20.py::test_alee_unified_cryptographic_erasure_on_withdrawal` | Erases access to application ciphertext; does not physically overwrite raw disk sectors or offline cold backups. |
| **Append-Only Merkle Transparency Log** | `app/services/transparency_service.py` | RFC 6962 compliant Merkle tree over canonical event commitments. Generates SHA-256 inclusion proofs and consistency proofs with Ed25519 Signed Tree Heads (STH). | `tests/test_phase_18_19_20.py::test_merkle_leaf_committed_atomically_with_report`<br>`test_merkle_inclusion_proof_verification` | Establishes append-only immutability of recorded events; does not prevent an operator from withholding unpublished records. |
| **Cryptographic Warrant Canary** | `app/services/canary_service.py`<br>`app/api/v1/endpoints/canary.py` | Periodic Ed25519-signed public statement asserting 0 gag orders or national security letters. Monotonically incrementing sequence and explicit validity window. | `tests/test_phase_18_19_20.py::test_warrant_canary_publishing_and_signature`<br>`test_canary_from_canary_mapping_and_expiry_semantics` | Canary expiration signals operator silence or potential legal compulsion; requires external party to monitor validity. |
| **Dead-Man's Switch** | `app/services/canary_service.py` | Administrators must check in with fresh MFA TOTP proofs every 14 days. If the check-in window lapses, the platform enters dead-man warning/tripped state. | `tests/test_phase_18_19_20.py::test_dead_man_switch_check_in_with_totp` | Protects against administrator incapacitation or coercion. |
| **Emergency Access Sealing** | `app/services/canary_service.py`<br>`app/api/v1/endpoints/moderator.py` | Administrator can engage emergency seal. Instantly revokes moderator plaintext decryption, blocks case exports, halts key re-wrapping, and prevents key destruction / retention sweeps. Anonymous submission, messaging, and tracking remain active. | `tests/test_phase_18_19_20.py::test_emergency_seal_enforcement_boundary` | Disengaging emergency seal requires fresh administrator TOTP verification. |
| **Dual-Control Quorum Governance** | `app/services/quorum_service.py` | High-impact administrative actions (case reopening, moderator role modification, webhook deletion) require proposal by one administrator and approval by another. | `tests/test_moderator_advanced.py` (Quorum test suite) | Enforced when `QUORUM_ENFORCE_*` settings are toggled. |
| **Transactional Outbox & Webhook Dispatch** | `app/services/outbox_service.py`<br>`app/services/webhook_service.py` | Atomic publishing of domain events in Postgres with distributed worker lease acquisition (`pg_try_advisory_lock`), exponential backoff, and dead-letter queues. | `tests/test_case_communication.py` | Egress webhooks enforce DNS rebinding SSRF protection (private IP blocking). |
| **Cryptographic Disaster Recovery Tooling** | `scripts/recovery_drill.py`<br>`scripts/backup_verify.py`<br>`scripts/restore_verify.py` | Automated 5-tier audit verifying backup manifest digests, KEK keyring coverage, evidence storage reconciliation, Merkle tree root consistency, and outbox lease reclamation. | `scripts/recovery_drill.py` (Passes in 0.07s) | Simulation drill validating cross-tier cryptographic consistency; does not test physical cold restore duration. |
