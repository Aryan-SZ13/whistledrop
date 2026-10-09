# WhistleDrop — Reliability & Operational Engineering
## Concurrency Controls, Fault Handling & Recovery Verification

---

## 1. Database Transaction Boundaries & Atomicity

In WhistleDrop, report submission, cryptographic key creation, transparency leaf appending, and domain event publishing must succeed or fail as a single atomic unit. A partial failure (e.g., database writes report but outbox fails) would compromise system integrity.

```mermaid
graph TD
    subgraph ACIDTransaction["Single PostgreSQL ACID Transaction Boundary"]
        T1["1. INSERT INTO reports<br/>(status, category, digest, version=1)"] --> T2["2. INSERT INTO case_encryption_keys<br/>(wrapped_dek, iv, tag, version)"]
        T2 --> T3["3. UPDATE reports SET<br/>description_encrypted, aad_version"]
        T3 --> T4["4. Lock MerkleTreeState FOR UPDATE<br/>INSERT INTO merkle_leaves"]
        T4 --> T5["5. INSERT INTO outbox_events<br/>(event='report.created', status='PENDING')"]
        T5 --> T6["6. INSERT INTO audit_logs<br/>(action='REPORT_SUBMITTED')"]
    end

    Commit["COMMIT Transaction"]
    Rollback["ROLLBACK Everything"]

    T6 -->|"All Steps OK"| Commit
    ACIDTransaction -->|"Any Exception"| Rollback

    style Commit fill:#059669,stroke:#34d399,color:#fff;
    style Rollback fill:#e11d48,stroke:#fda4af,color:#fff;
```

> **Verified Runtime Invariant:** If any cryptographic error, lock timeout, or constraint violation occurs during submission, `db.rollback()` executes, ensuring zero orphan rows or uncommitted keys exist. Tested in [`tests/test_reports.py::test_transaction_rollback_on_failure`](../tests/test_reports.py).

---

## 2. Transactional Outbox Lifecycle & Worker Leases

To guarantee reliable asynchronous event publishing without dual-write inconsistencies, WhistleDrop uses an in-process transactional outbox pattern with mutual-exclusion worker leases:

```mermaid
stateDiagram-v2
    [*] --> PENDING : Atomically created with domain action

    PENDING --> CLAIMED : Worker acquires lease via advisory lock
    
    CLAIMED --> DISPATCHED : Webhook delivered (HTTP 2xx)
    CLAIMED --> FAILED : Delivery timeout or network error (HTTP 4xx/5xx)

    FAILED --> PENDING : Exponential backoff retry (retry_count < 5)
    FAILED --> DEAD_LETTER : Max retries exceeded (retry_count >= 5)

    CLAIMED --> PENDING : Lease expired without completion (Crash Recovery)

    DISPATCHED --> [*]
    DEAD_LETTER --> [*]
```

### Worker Concurrency Invariants
- **Multi-Worker Safety:** Workers claim batches using `SELECT ... FOR UPDATE SKIP LOCKED` combined with PostgreSQL Advisory Locks (`pg_try_advisory_lock`), preventing split-brain event processing across container replicas.
- **Lease Expiry Reclamation:** If a background worker crashes mid-delivery, its lease expires (`lease_expires_at <= now()`), allowing surviving workers to safely reclaim the pending event.

---

## 3. Atomic Merkle Leaf Allocation Under Concurrency

Under concurrent report submissions, leaf index sequence numbers must remain strictly contiguous without gaps or collisions. WhistleDrop resolves this via native database conflict handling and row-level locking:

```mermaid
sequenceDiagram
    autonumber
    actor Worker1 as Ingestion Thread A
    actor Worker2 as Ingestion Thread B
    participant StateTable as merkle_tree_state (Singleton id=1)
    participant LeafTable as merkle_leaves

    Worker1->>StateTable: INSERT ... ON CONFLICT (id) DO NOTHING
    Worker2->>StateTable: INSERT ... ON CONFLICT (id) DO NOTHING
    
    Worker1->>StateTable: SELECT * WHERE id = 1 FOR UPDATE (Acquires Row Lock)
    Note over Worker2: Thread B BLOCKED waiting for Row Lock on id=1
    
    Worker1->>Worker1: Assign leaf_index = next_leaf_index (e.g. Index 10)
    Worker1->>LeafTable: INSERT INTO merkle_leaves (index=10, hash, ...)
    Worker1->>StateTable: UPDATE merkle_tree_state SET next_leaf_index = 11, tree_size = 11
    Worker1-->>StateTable: Commit Transaction (Releases Lock)
    
    StateTable-->>Worker2: Thread B Acquires Row Lock
    Worker2->>Worker2: Assign leaf_index = next_leaf_index (Index 11 - Perfectly Contiguous!)
    Worker2->>LeafTable: INSERT INTO merkle_leaves (index=11, hash, ...)
    Worker2->>StateTable: UPDATE merkle_tree_state SET next_leaf_index = 12, tree_size = 12
    Worker2-->>StateTable: Commit Transaction (Releases Lock)
```

---

## 4. Failure Modes & Graceful Degradation Matrix

The system enforces explicit fail-closed or graceful degradation behaviors when external infrastructure fails:

| Component Outage | Failure Behavior | Security & Operational Rationale | Test Reference |
| :--- | :---: | :--- | :--- |
| **Redis Cache Outage** | **FAILS CLOSED** | If Redis is down, rate limiters reject submissions and lookups with HTTP 503 / 429 rather than allowing unmetered brute-force attacks. | `test_redis_outage_fails_closed_on_submission`<br>`test_redis_outage_fails_closed_on_lookup` |
| **ClamAV Antivirus Outage** | **QUARANTINES** | If ClamAV is unreachable during upload, files remain in `quarantine/` with status `PENDING_SCAN` and are never promoted to `approved/`. | `tests/test_evidence.py` |
| **PostgreSQL Outage** | **FAILS CLOSED** | Transactions abort immediately; generic sanitized HTTP 500 returned with zero database connection strings or internal errors leaked. | `test_tracking_database_error_safety` |
| **Emergency Seal Engaged** | **RESTRICTED** | Halts moderator decryption and case exports; anonymous intake and tracking continue functioning. | `test_emergency_seal_enforcement_boundary` |

---

## 5. Automated Disaster Recovery Verification Scope

WhistleDrop includes automated cryptographic recovery verification tooling (`scripts/recovery_drill.py`). The drill simulates disaster recovery consistency across all 5 architectural tiers:

```mermaid
graph LR
    Drill["scripts/recovery_drill.py<br/>(Simulation Drill: 0.06s)"]
    
    Drill --> T1["Tier 1: Keyring Validation<br/>Active KEK covers all stored case DEKs"]
    Drill --> T2["Tier 2: Evidence Attachment Audit<br/>Filesystem objects match DB attachment records"]
    Drill --> T3["Tier 3: Merkle Consistency Audit<br/>Recalculates RFC 6962 root from canonical leaves"]
    Drill --> T4["Tier 4: Outbox Lease Reclamation<br/>Resets stuck leases from crashed worker nodes"]
    Drill --> T5["Tier 5: Backup Archive Integrity<br/>Verifies backup_manifest.json SHA-256 digests"]
```

> **Factual Grounding & Limitation Disclosure**:
> The recovery drill evaluates database and storage cryptographic consistency. It executes in **0.06 seconds** locally.
> It is an automated **verification drill**; it does **not** perform physical backup restore over the network or measure cold cluster re-provisioning times. Target RTO (< 120s) and Target RPO (< 60s) are design objectives.
