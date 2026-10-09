# WhistleDrop — Local Microbenchmark Report

This document records empirical microbenchmark performance, latency percentiles, and operation throughput measured on a local WhistleDrop instance.

> **Scope & Limitations:**
> This report reflects single-node local microbenchmarks executed sequentially against local PostgreSQL 16 and Redis 7 instances.
> Sample counts are N=25 to 50 iterations per operation. Calculating tail percentiles like p99 from 25–50 observations is statistically preliminary and does not constitute a reliable production latency SLA or multi-node concurrent saturation metric.
> It measures raw cryptographic and transactional algorithmic latency, not distributed production cluster capacity or end-to-end network transit. Future load testing will evaluate multi-node concurrent saturation.

**Benchmark Date:** 2026-10-04 20:06:03 UTC  
**Environment:** Python 3.13 / FastAPI / PostgreSQL 16 (NullPool Engine) / Redis 7  
**Hardware Profile:** Apple Silicon (macOS) / Multi-threaded Async Runtime  

---

## 1. Executive Summary & Microbenchmark Latencies

| Pipeline Stage | Target Latency (p95) | Measured p50 | Measured p95 | Measured p99 | Throughput | Scope |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Merkle Leaf Commitment** | < 15.0 ms | 1.8 ms | 4.81 ms | 36.48 ms | 336.5 ops/sec | Local microbenchmark |
| **ALEE AES-256-GCM Encryption** | < 10.0 ms | 0.97 ms | 1.47 ms | 5.87 ms | 933.7 ops/sec | Local microbenchmark |
| **ALEE AES-256-GCM Decryption** | < 10.0 ms | 0.61 ms | 1.32 ms | 4.02 ms | 1386.7 ops/sec | Local microbenchmark |
| **Full Report Ingestion Pipeline** | < 300.0 ms | 8.48 ms | 20.86 ms | 28.2 ms | 94.8 ops/sec | Local microbenchmark |
| **Anonymous Case Tracking** | < 100.0 ms | 1.11 ms | 5.98 ms | 7.43 ms | 501.5 ops/sec | Local microbenchmark |

---

## 2. Granular Operation Analysis

### A. Full Report Ingestion Pipeline
- **Workload Performed:**
  1. CSPRNG case code generation & Argon2id salt derivation
  2. Database report row transaction allocation
  3. Envelope Key generation (AES-256 DEK wrapped under active KEK)
  4. Application-Level Envelope Encryption (ALEE) with authenticated AAD binding
  5. RFC 6962 Merkle tree index lock acquisition & leaf hashing
  6. Transactional Outbox event generation
  7. Audit log commitment
- **Measured Metrics:**
  - **Execution:** Sequential microbenchmark
  - **Iterations:** 25
  - **Mean Latency:** 10.55 ms
  - **p50:** 8.48 ms
  - **p95:** 20.86 ms
  - **p99:** 28.2 ms
  - **Throughput:** 94.8 submissions/sec

### B. Append-Only Merkle Transparency Log Commitment
- **Workload Performed:**
  - Row-level lock on singleton `MerkleTreeState` (`SELECT ... FOR UPDATE`)
  - Canonical length-prefixed binary serialization
  - RFC 6962 leaf hashing (`SHA-256(0x00 || canonical_bytes)`)
  - Leaf row persistence & contiguous index increment
- **Measured Metrics:**
  - **Execution:** Sequential microbenchmark
  - **Iterations:** 50
  - **Mean Latency:** 2.97 ms
  - **p50:** 1.8 ms
  - **p95:** 4.81 ms
  - **p99:** 36.48 ms
  - **Throughput:** 336.5 leaves/sec

### C. Application-Level Envelope Cryptography (ALEE)
- **Encryption Workflow:** DEK generation, AES-256-GCM payload encryption with AAD context binding, KEK wrapping, persistence.
  - **p50:** 0.97 ms | **p95:** 1.47 ms | **Throughput:** 933.7 ops/sec (50 iterations)
- **Decryption Workflow:** KEK unwrapping, AAD verification, AES-256-GCM authentication tag check, plaintext return.
  - **p50:** 0.61 ms | **p95:** 1.32 ms | **Throughput:** 1386.7 ops/sec (50 iterations)

### D. Anonymous Case Tracking Retrieval
- **Workload Performed:**
  - Case code derivation and lookup
  - Public timeline assembly
  - Filtered privacy-preserving response creation
- **Measured Metrics:**
  - **Execution:** Sequential microbenchmark
  - **Iterations:** 25
  - **p50:** 1.11 ms | **p95:** 5.98 ms | **Throughput:** 501.5 queries/sec

---

## 3. Disaster Recovery & Continuity Drill Evidence

Measurements gathered from `scripts/recovery_drill.py`:
- **Target RTO (Objective):** < 120.0s (Documented target)
- **Target RPO (Objective):** < 60.0s (Documented target)
- **Recovery Verification Drill Duration:** 0.06s across all 5 tiers (DB, Storage, Keyring, Transparency, Outbox).
- **Scope & Limitations:** The automated drill evaluates database and storage cryptographic consistency. It is a local verification drill and does not measure physical network transfer or cold cluster re-provisioning times.

---

## 4. Three-Tier Reproducibility Architecture

WhistleDrop separates workload execution, metric persistence, and chart generation:
1. **Workload Execution (`scripts/benchmark.py`)**: Executes live cryptographic and database transaction operations, recording timing intervals via `time.perf_counter()`.
2. **Summary Dataset (`docs/benchmark_data.json` & `docs/benchmark_data.csv`)**: Holds empirical summary statistics (p50, p95, p99, throughput, and sample size $N$) captured during the benchmark run.
3. **Visualization Generator (`scripts/generate_figures.py`)**: Deterministically renders vector SVG figures in `docs/figures/` from `benchmark_data.json`.

> **Data Integrity Clarification**:  
> `benchmark_data.json` reproduces the **plotted summary statistics**, and `generate_figures.py` reproduces the **visualizations**. Summary statistics alone are not raw observations and cannot independently reproduce the original measurement distributions. Running `scripts/benchmark.py` executes fresh, live workloads that will produce slightly varied measurements depending on CPU scheduling and host load.

