# WhistleDrop — Disaster Recovery & Business Continuity Manual

This manual defines the multi-tier dependency architecture, recovery point objectives (RPO), recovery time objectives (RTO), automated verification tools, and incident runbooks for WhistleDrop.

---

## 1. Multi-Tier Dependency Graph

WhistleDrop's operational state is partitioned across five interdependent tiers:

```
┌─────────────────────────────────────────────────────────────┐
│ Tier 1: Relational Metadata (PostgreSQL 16)                │
│  - Case Records, Audit Trails, Outbox, Merkle Leaves        │
└──────────────────────────────┬──────────────────────────────┘
                               │ References
       ┌───────────────────────┼──────────────────────────────┐
       ▼                       ▼                              ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ Tier 2: Storage  │  │ Tier 3: Keyring  │  │ Tier 4: Merkle   │
│  - Evidence Files│  │  - AES KEK Keyring│  │  - Signed Heads  │
│  - Approved/Shred│  │  - Active Version │  │  - Leaf Tree Root│
└──────────────────┘  └──────────────────┘  └──────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Tier 5: Volatile Cache & Transient State (Redis 7)          │
│  - Session Blacklist, Sliding Window Rate Limiting          │
└─────────────────────────────────────────────────────────────┘
```

### Dependency Rules:
1. **Database $\rightarrow$ Evidence Storage:** Every `ACTIVE` attachment record in PostgreSQL must have a matching file in `storage/evidence/approved/`. Files without DB records are orphans; DB records without files represent data loss.
2. **Database $\rightarrow$ KEK Keyring:** Every `case_encryption_keys.key_version` in PostgreSQL must exist in `PAYLOAD_KEK_KEYRING`. If a version is missing, affected cases cannot be decrypted.
3. **Database $\rightarrow$ Merkle Tree:** `merkle_tree_state.tree_size` must equal the exact count of committed `merkle_leaves` rows, and recomputing the tree root must match the published Signed Tree Head prefix.
4. **Outbox Recovery:** Orphaned worker leases from crashed workers must be reset to `PENDING` to resume event dispatch without duplicate sends.

---

## 2. Continuity Targets & Empirical Evidence

| Metric | Business Target / Objective | Verification Drill Duration | Status |
| :--- | :--- | :--- | :--- |
| **Recovery Time Objective (RTO)** | < 120.0 seconds (Target) | N/A (Simulated verification drill) | **ASSUMED TARGET** |
| **Recovery Point Objective (RPO)** | < 60.0 seconds (Target) | N/A (Simulated verification drill) | **ASSUMED TARGET** |
| **Recovery Verification Drill Duration** | < 10.0 seconds | **0.06 seconds** (Full 5-tier audit) | **EXCEEDED** |

*Measured via `scripts/recovery_drill.py`. Note: This automated drill verifies cross-tier cryptographic consistency and dependency graph health; physical restore duration from cold storage will depend on infrastructure data transfer rates and snapshot volume.*

---

## 3. Automated Disaster Recovery Tooling

WhistleDrop includes three automated verification and recovery scripts:

### A. Backup Integrity Verification (`scripts/backup_verify.py`)
Validates a backup snapshot directory without modifying any application state:
```bash
python scripts/backup_verify.py /path/to/backup_dir
```
- Verifies `backup_manifest.json` against `backup_manifest.sha256`
- Verifies SHA-256 digests of all bundled evidence files
- Validates KEK keyring version coverage

### B. Live Restore & Dependency Audit (`scripts/restore_verify.py`)
Performs a deep cryptographic audit of a newly restored or running instance:
```bash
python scripts/restore_verify.py
```
- Reconciles database evidence attachment records with filesystem objects
- Verifies KEK keyring contains all versions required by active case DEKs
- Audits RFC 6962 Merkle tree state and recomputes the live root hash
- Reclaims stuck outbox leases from crashed background workers

### C. Automated Recovery Drill Simulation (`scripts/recovery_drill.py`)
Simulates an end-to-end disaster scenario: generates a backup manifest, validates archive integrity, and audits live state:
```bash
python scripts/recovery_drill.py
```

---

## 4. Disaster Recovery Runbooks

### Runbook 1: Cold Instance Restore
1. Restore PostgreSQL database from latest physical WAL backup or `pg_dump`.
2. Restore evidence files to `$EVIDENCE_STORAGE_PATH/approved/`.
3. Provide the full KEK keyring in `PAYLOAD_KEK_KEYRING` environment variable.
4. Run pre-flight verification:
   ```bash
   python scripts/restore_verify.py
   ```
5. Ensure the script outputs `[+] RESTORE VERIFICATION PASSED: HEALTHY`.
6. Start API and worker processes.

### Runbook 2: Remediating Evidence Storage Drift
If `restore_verify.py` reports `missing_files` or `orphan_files`:
- **Orphan Files (Files on disk without DB records):** Inspect timestamp. If older than 24 hours, move to quarantined storage for review.
- **Missing Files (DB record without disk object):** Investigate backup storage replicas. If permanently lost, flag evidence record as `SHRED_FAILED` to alert review team.

### Runbook 3: Missing KEK Version Remediation
If `restore_verify.py` reports `missing_versions: [N]`:
1. The platform will fail closed for cases wrapped under version `N`.
2. Locate the historical KEK version `N` from cold secret vault.
3. Append `"N": "<key_hex>"` into `PAYLOAD_KEK_KEYRING` JSON dictionary.
4. Re-run `python scripts/restore_verify.py` to confirm resolution.
