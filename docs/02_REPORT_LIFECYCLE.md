# WhistleDrop — Report Lifecycle & Workflows
## Sequence Traces, Data Flows & State Machines

---

## 1. Anonymous Report Submission Workflow (Sequence A)

The submission sequence illustrates how a confidential report is ingested, encrypted, and recorded in the transparency log without collecting any reporter identity:

```mermaid
sequenceDiagram
    autonumber
    actor Reporter as Anonymous Whistleblower
    participant UI as React Frontend
    participant API as FastAPI Ingress (/api/v1/reports)
    participant RateLimit as Redis Rate Limiter
    participant Sec as Security Engine (app/core/security.py)
    participant ALEE as Payload Encryption (ALEE)
    participant Merkle as Transparency Service
    participant DB as PostgreSQL Database
    participant Outbox as Transactional Outbox

    Reporter->>UI: Fills form (Category, Narrative, optional Evidence)
    UI->>UI: Client validation (Narrative min 10 chars, no identity fields)
    UI->>API: POST /api/v1/reports (JSON payload)
    
    API->>RateLimit: Check submission rate (5/300s window by Client IP)
    RateLimit-->>API: Quota OK
    
    API->>API: Pydantic validation (ReportCreate schema, extra='forbid')
    
    API->>Sec: Generate CSPRNG Case Code & HMAC Digest
    Note over Sec: case_code = secrets.token_urlsafe(32)<br/>digest = HMAC-SHA256(CASE_CODE_SECRET, case_code)
    Sec-->>API: (case_code, case_code_digest)
    
    API->>DB: Begin Atomic ACID Transaction
    API->>DB: INSERT INTO reports (status='SUBMITTED', digest, version=1)
    
    API->>ALEE: Encrypt Narrative Payload (report_id, narrative)
    Note over ALEE: Generates random 256-bit DEK<br/>Encrypts DEK under active KEK<br/>AES-256-GCM encrypts narrative with AAD
    ALEE->>DB: INSERT INTO case_encryption_keys (wrapped_dek, version)
    ALEE->>DB: UPDATE reports SET description_encrypted, iv, tag, aad_version
    
    API->>Merkle: Commit Leaf (event='report.submitted', payload_digest)
    Note over Merkle: SELECT ... FOR UPDATE on singleton MerkleTreeState<br/>Computes canonical binary leaf<br/>Allocates contiguous sequence index
    Merkle->>DB: INSERT INTO merkle_leaves (index, leaf_hash, canonical_bytes)
    Merkle->>DB: UPDATE merkle_tree_state SET tree_size = tree_size + 1
    
    API->>Outbox: Publish Outbox Event (event='report.created')
    Outbox->>DB: INSERT INTO outbox_events (status='PENDING')
    
    API->>DB: Commit Transaction
    
    API-->>UI: HTTP 201 Created (case_code, status, category, created_at)
    Note over UI: case_code stored STRICTLY IN-MEMORY<br/>Never written to localStorage, cookies, or URL!
    UI-->>Reporter: Displays case code once & warning to save code securely
```

---

## 2. Anonymous Case Tracking Workflow (Sequence B)

Reporters track incident progress using their case code. The case code is transmitted exclusively via request body, preventing leakage into URLs, referer headers, or access logs:

```mermaid
sequenceDiagram
    autonumber
    actor Reporter as Anonymous Whistleblower
    participant UI as React Frontend
    participant API as FastAPI Tracking (/api/v1/reports/track)
    participant RateLimit as Redis Rate Limiter
    participant Sec as Security Engine
    participant ALEE as Payload Encryption (ALEE)
    participant DB as PostgreSQL Database

    Reporter->>UI: Enters case code (in memory)
    UI->>API: POST /api/v1/reports/track (body: {"case_code": "wdc_..."})
    
    API->>RateLimit: Check lookup rate (10/60s IP & 100/60s global safeguard)
    RateLimit-->>API: Quota OK
    
    API->>Sec: Derive HMAC-SHA256 Digest of Case Code
    Sec-->>API: case_code_digest
    
    API->>DB: SELECT * FROM reports WHERE case_code_digest = digest
    DB-->>API: Report record (or 404 Not Found)
    
    Note over API: Query public updates with least-privilege column selection:
    API->>DB: SELECT message, created_at FROM report_updates<br/>WHERE report_id = id AND type = 'PUBLIC_UPDATE'<br/>ORDER BY created_at ASC
    DB-->>API: List of public updates
    
    opt If update messages are encrypted under ALEE
        API->>ALEE: Decrypt message (context=ANONYMOUS_PUBLIC_UPDATE)
        ALEE-->>API: Decrypted update text
    end
    
    Note over API: Filter confidential fields:<br/>• Moderator IDs & notes: EXCLUDED<br/>• Plaintext case code: EXCLUDED<br/>• Internal database IDs: EXCLUDED
    
    API-->>UI: HTTP 200 OK (ReportTrackingResponse)
    UI-->>Reporter: Renders current status badge and timeline of public updates
```

### Realistic Safe API Request & Response

#### Request
```http
POST /api/v1/reports/track HTTP/1.1
Host: api.whistledrop.org
Content-Type: application/json

{
  "case_code": "wdc_TdGlKfZK3C_BheWenUTr9L8VLCZXJiso"
}
```

#### Response
```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store, no-cache, must-revalidate, private
Pragma: no-cache

{
  "status": "UNDER_REVIEW",
  "category": "CORRUPTION",
  "created_at": "2026-10-09T16:49:24.608275Z",
  "updates": [
    {
      "message": "Independent compliance committee has initiated an internal financial review.",
      "created_at": "2026-10-09T16:49:44.589853Z"
    }
  ]
}
```

---

## 3. Moderator Review & Triage Workflow (Sequence C)

Authorized personnel authenticate, inspect cases, advance statuses, and attach public updates under Optimistic Concurrency Control (OCC):

```mermaid
sequenceDiagram
    autonumber
    actor Moderator as Staff / Investigator
    participant UI as Moderator Portal
    participant API as FastAPI Moderator Routes
    participant Auth as Auth & MFA Service
    participant ModSvc as Moderator Service
    participant ALEE as Payload Encryption (ALEE)
    participant DB as PostgreSQL Database

    Moderator->>UI: Enters credentials (username, password)
    UI->>API: POST /api/v1/moderator/auth/login
    API->>Auth: Verify Argon2id password hash
    Auth-->>API: Issue 30-min JWT Bearer Token
    API-->>UI: Token returned
    
    Moderator->>UI: Clicks incident in triage queue
    UI->>API: GET /api/v1/moderator/reports/{id} (Bearer Token)
    API->>Auth: Validate JWT & check active session table
    API->>ModSvc: Fetch report details
    ModSvc->>ALEE: Decrypt case narrative using case DEK
    ALEE-->>ModSvc: Decrypted narrative
    ModSvc-->>API: Full case details (version=1)
    API-->>UI: Renders incident details, narrative, and evidence metadata
    
    Moderator->>UI: Changes status to UNDER_REVIEW
    UI->>API: PATCH /api/v1/moderator/reports/{id}/status<br/>{"status": "UNDER_REVIEW", "expected_version": 1}
    
    API->>ModSvc: Update status with OCC verification
    Note over ModSvc: Verifies valid transition:<br/>SUBMITTED -> UNDER_REVIEW<br/>Checks report.version == expected_version
    ModSvc->>DB: UPDATE reports SET status='UNDER_REVIEW', version=2<br/>WHERE id=id AND version=1
    ModSvc->>DB: INSERT INTO audit_logs (action='STATUS_CHANGED', version=2)
    ModSvc-->>API: Updated report object (version=2)
    API-->>UI: Status updated successfully
```

---

## 4. Report Lifecycle State Machine (Diagram D)

The lifecycle state machine enforces strict progression rules. Reports enter as `SUBMITTED`, progress through triage, and reach terminal closure:

```mermaid
stateDiagram-v2
    [*] --> SUBMITTED : Anonymous Report Created

    SUBMITTED --> UNDER_REVIEW : Moderator starts investigation
    
    UNDER_REVIEW --> RESOLVED : Investigation completed & findings addressed
    UNDER_REVIEW --> DISMISSED : Report unsubstantiated or invalid

    SUBMITTED --> WITHDRAWN : Reporter withdraws with case code
    UNDER_REVIEW --> WITHDRAWN : Reporter withdraws with case code

    state TerminalClosure {
        RESOLVED
        DISMISSED
        WITHDRAWN
    }

    note right of TerminalClosure
        Terminal States:
        • Regular moderators CANNOT alter or transition closed cases.
        • WITHDRAWN triggers irreversible cryptographic erasure of the DEK.
        • Reopening RESOLVED/DISMISSED requires ADMIN role + min 10-char reason + Quorum (if enabled).
    end note

    RESOLVED --> UNDER_REVIEW : Admin Reopen (Reason Required)
    DISMISSED --> UNDER_REVIEW : Admin Reopen (Reason Required)

    WITHDRAWN --> [*] : Key Destroyed (Permanently Irreversible)
```

### Transition Validation Rules

| Current Status | Target Status | Permitted Actor | Validation Rule / Requirement |
| :--- | :--- | :---: | :--- |
| `SUBMITTED` | `UNDER_REVIEW` | `MODERATOR` / `ADMIN` | Expected version match (OCC). Standard triage initiation. |
| `UNDER_REVIEW` | `RESOLVED` | `MODERATOR` / `ADMIN` | Expected version match (OCC). Case marked permanently addressed. |
| `UNDER_REVIEW` | `DISMISSED` | `MODERATOR` / `ADMIN` | Expected version match (OCC). Case dismissed with explanation. |
| `SUBMITTED` / `UNDER_REVIEW` | `WITHDRAWN` | Anonymous Reporter | Verified case code. Irreversibly zeroes out the case DEK. |
| `RESOLVED` / `DISMISSED` | `UNDER_REVIEW` | `ADMIN` Only | Requires `reopen_reason` (min 10 characters). Subject to Dual-Control Quorum when enabled. |
| *Any Other* | *Any Other* | — | **REJECTED (HTTP 400 Bad Request)**. Illegal transition. |
