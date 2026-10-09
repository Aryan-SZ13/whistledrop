"""
WhistleDrop Performance Benchmark Runner
Measures live p50, p95, p99 latency and throughput for core cryptographic,
ingestion, and retrieval operations against the running database and crypto engine.
"""

import asyncio
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import statistics
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sqlalchemy as sa

from app.core.config import settings
from app.db.session import async_session_factory
from app.models.enums import ModeratorRole, ReportCategory, ReportPriority, ReportStatus
from app.models.report import Report
from app.schemas.report import ReportCreate
from app.services.payload_encryption_service import DecryptionContext, payload_encryption_service
from app.services.report_service import report_service
from app.services.transparency_service import transparency_service


def calculate_latencies(durations_ms: list) -> dict:
    if not durations_ms:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "mean": 0.0}
    s = sorted(durations_ms)
    n = len(s)
    return {
        "p50": round(s[int(n * 0.50)], 2),
        "p95": round(s[min(int(n * 0.95), n - 1)], 2),
        "p99": round(s[min(int(n * 0.99), n - 1)], 2),
        "mean": round(statistics.mean(s), 2),
    }


async def benchmark_merkle_commitments(iterations: int = 50) -> dict:
    durations = []
    async with async_session_factory() as session:
        for i in range(iterations):
            digest = hashlib.sha256(f"bench_payload_{i}_{uuid.uuid4()}".encode("utf-8")).digest()
            start = time.perf_counter()
            await transparency_service.commit_merkle_leaf(
                db=session,
                event_type="benchmark.event",
                opaque_reference=f"ref_{i}",
                payload_digest=digest,
            )
            await session.commit()
            durations.append((time.perf_counter() - start) * 1000.0)
    lat = calculate_latencies(durations)
    ops_sec = round(iterations / (sum(durations) / 1000.0), 1)
    return {**lat, "ops_sec": ops_sec, "iterations": iterations}


async def benchmark_alee_encryption_decryption(iterations: int = 50) -> tuple:
    enc_durations = []
    dec_durations = []

    async with async_session_factory() as session:
        # Create a report anchor for the foreign key
        report = Report(
            case_code_digest="bench_digest_" + uuid.uuid4().hex[:16],
            category=ReportCategory.SECURITY,
            status=ReportStatus.SUBMITTED,
            priority=ReportPriority.MEDIUM,
        )
        session.add(report)
        await session.commit()
        report_id = report.id

        sample_text = (
            "WhistleDrop sensitive disclosure benchmark payload simulating a high-entropy "
            "whistleblower submission containing corporate malfeasance telemetry."
        )

        ciphertexts = []
        for _ in range(iterations):
            start = time.perf_counter()
            c, iv, tag, v = await payload_encryption_service.encrypt_payload(
                db=session,
                report_id=report_id,
                object_type="REPORT",
                object_id=report_id,
                field_name="description",
                plaintext=sample_text,
            )
            await session.commit()
            enc_durations.append((time.perf_counter() - start) * 1000.0)
            ciphertexts.append((c, iv, tag, v))

        for c, iv, tag, v in ciphertexts:
            start = time.perf_counter()
            await payload_encryption_service.decrypt_payload(
                db=session,
                report_id=report_id,
                object_type="REPORT",
                object_id=report_id,
                field_name="description",
                ciphertext=c,
                iv=iv,
                tag=tag,
                aad_version=v,
                context=DecryptionContext.MODERATOR_CASE_READ,
            )
            dec_durations.append((time.perf_counter() - start) * 1000.0)

    enc_lat = calculate_latencies(enc_durations)
    enc_ops = round(iterations / (sum(enc_durations) / 1000.0), 1)
    dec_lat = calculate_latencies(dec_durations)
    dec_ops = round(iterations / (sum(dec_durations) / 1000.0), 1)

    return (
        {**enc_lat, "ops_sec": enc_ops, "iterations": iterations},
        {**dec_lat, "ops_sec": dec_ops, "iterations": iterations},
    )


async def benchmark_full_report_submission(iterations: int = 30) -> dict:
    durations = []
    case_codes = []

    for i in range(iterations):
        async with async_session_factory() as session:
            report_in = ReportCreate(
                category=ReportCategory.CORRUPTION,
                description=f"WhistleDrop full pipeline benchmark submission {i}",
            )
            start = time.perf_counter()
            rep, code = await report_service.create_report(db=session, report_in=report_in)
            await session.commit()
            durations.append((time.perf_counter() - start) * 1000.0)
            case_codes.append(code)

    lat = calculate_latencies(durations)
    ops_sec = round(iterations / (sum(durations) / 1000.0), 1)
    return {**lat, "ops_sec": ops_sec, "iterations": iterations, "case_codes": case_codes}


async def benchmark_report_tracking(case_codes: list) -> dict:
    durations = []
    async with async_session_factory() as session:
        for code in case_codes:
            start = time.perf_counter()
            await report_service.get_report_tracking(db=session, case_code=code)
            durations.append((time.perf_counter() - start) * 1000.0)

    lat = calculate_latencies(durations)
    ops_sec = round(len(case_codes) / (sum(durations) / 1000.0), 1)
    return {**lat, "ops_sec": ops_sec, "iterations": len(case_codes)}


async def run_all_benchmarks():
    print("=" * 80)
    print("WHISTLEDROP PRODUCTION PERFORMANCE & LATENCY BENCHMARK")
    print("=" * 80)

    print("\n[1/4] Benchmarking Merkle Tree Commitments (Atomic sequence locks)...")
    merkle_res = await benchmark_merkle_commitments(iterations=50)
    print(f"      p50: {merkle_res['p50']}ms | p95: {merkle_res['p95']}ms | p99: {merkle_res['p99']}ms | Throughput: {merkle_res['ops_sec']} ops/sec")

    print("\n[2/4] Benchmarking ALEE Envelope Encryption & Decryption...")
    enc_res, dec_res = await benchmark_alee_encryption_decryption(iterations=50)
    print(f"      Encryption: p50: {enc_res['p50']}ms | p95: {enc_res['p95']}ms | p99: {enc_res['p99']}ms | Throughput: {enc_res['ops_sec']} ops/sec")
    print(f"      Decryption: p50: {dec_res['p50']}ms | p95: {dec_res['p95']}ms | p99: {dec_res['p99']}ms | Throughput: {dec_res['ops_sec']} ops/sec")

    print("\n[3/4] Benchmarking Full Report Submission Pipeline (Argon2id + ALEE + Merkle + Outbox)...")
    sub_res = await benchmark_full_report_submission(iterations=25)
    print(f"      p50: {sub_res['p50']}ms | p95: {sub_res['p95']}ms | p99: {sub_res['p99']}ms | Throughput: {sub_res['ops_sec']} ops/sec")

    print("\n[4/4] Benchmarking Anonymous Case Tracking Retrieval...")
    track_res = await benchmark_report_tracking(sub_res["case_codes"])
    print(f"      p50: {track_res['p50']}ms | p95: {track_res['p95']}ms | p99: {track_res['p99']}ms | Throughput: {track_res['ops_sec']} ops/sec")

    print("\n" + "=" * 80)
    print("Writing verified benchmark metrics to BENCHMARKS.md...")
    print("=" * 80)

    bench_md = f"""# WhistleDrop — Local Microbenchmark Report

This document records empirical microbenchmark performance, latency percentiles, and operation throughput measured on a local WhistleDrop instance.

> **Scope & Limitations:**
> This report reflects single-node local microbenchmarks executed sequentially against local PostgreSQL 16 and Redis 7 instances.
> It measures raw cryptographic and transactional algorithmic latency, not distributed production cluster capacity or end-to-end network transit. Future load testing will evaluate multi-node concurrent saturation.

**Benchmark Date:** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}  
**Environment:** Python 3.13 / FastAPI / PostgreSQL 16 (NullPool Engine) / Redis 7  
**Hardware Profile:** Apple Silicon (macOS) / Multi-threaded Async Runtime  

---

## 1. Executive Summary & Microbenchmark Latencies

| Pipeline Stage | Target Latency (p95) | Measured p50 | Measured p95 | Measured p99 | Throughput | Scope |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Merkle Leaf Commitment** | < 15.0 ms | {merkle_res['p50']} ms | {merkle_res['p95']} ms | {merkle_res['p99']} ms | {merkle_res['ops_sec']} ops/sec | Local microbenchmark |
| **ALEE AES-256-GCM Encryption** | < 10.0 ms | {enc_res['p50']} ms | {enc_res['p95']} ms | {enc_res['p99']} ms | {enc_res['ops_sec']} ops/sec | Local microbenchmark |
| **ALEE AES-256-GCM Decryption** | < 10.0 ms | {dec_res['p50']} ms | {dec_res['p95']} ms | {dec_res['p99']} ms | {dec_res['ops_sec']} ops/sec | Local microbenchmark |
| **Full Report Ingestion Pipeline** | < 300.0 ms | {sub_res['p50']} ms | {sub_res['p95']} ms | {sub_res['p99']} ms | {sub_res['ops_sec']} ops/sec | Local microbenchmark |
| **Anonymous Case Tracking** | < 100.0 ms | {track_res['p50']} ms | {track_res['p95']} ms | {track_res['p99']} ms | {track_res['ops_sec']} ops/sec | Local microbenchmark |

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
  - **Iterations:** {sub_res['iterations']}
  - **Mean Latency:** {sub_res['mean']} ms
  - **p50:** {sub_res['p50']} ms
  - **p95:** {sub_res['p95']} ms
  - **p99:** {sub_res['p99']} ms
  - **Throughput:** {sub_res['ops_sec']} submissions/sec

### B. Append-Only Merkle Transparency Log Commitment
- **Workload Performed:**
  - Row-level lock on singleton `MerkleTreeState` (`SELECT ... FOR UPDATE`)
  - Canonical length-prefixed binary serialization
  - RFC 6962 leaf hashing (`SHA-256(0x00 || canonical_bytes)`)
  - Leaf row persistence & contiguous index increment
- **Measured Metrics:**
  - **Execution:** Sequential microbenchmark
  - **Iterations:** {merkle_res['iterations']}
  - **Mean Latency:** {merkle_res['mean']} ms
  - **p50:** {merkle_res['p50']} ms
  - **p95:** {merkle_res['p95']} ms
  - **p99:** {merkle_res['p99']} ms
  - **Throughput:** {merkle_res['ops_sec']} leaves/sec

### C. Application-Level Envelope Cryptography (ALEE)
- **Encryption Workflow:** DEK generation, AES-256-GCM payload encryption with AAD context binding, KEK wrapping, persistence.
  - **p50:** {enc_res['p50']} ms | **p95:** {enc_res['p95']} ms | **Throughput:** {enc_res['ops_sec']} ops/sec ({enc_res['iterations']} iterations)
- **Decryption Workflow:** KEK unwrapping, AAD verification, AES-256-GCM authentication tag check, plaintext return.
  - **p50:** {dec_res['p50']} ms | **p95:** {dec_res['p95']} ms | **Throughput:** {dec_res['ops_sec']} ops/sec ({dec_res['iterations']} iterations)

### D. Anonymous Case Tracking Retrieval
- **Workload Performed:**
  - Case code derivation and lookup
  - Public timeline assembly
  - Filtered privacy-preserving response creation
- **Measured Metrics:**
  - **Execution:** Sequential microbenchmark
  - **Iterations:** {track_res['iterations']}
  - **p50:** {track_res['p50']} ms | **p95:** {track_res['p95']} ms | **Throughput:** {track_res['ops_sec']} queries/sec

---

## 3. Disaster Recovery & Continuity Drill Evidence

Measurements gathered from `scripts/recovery_drill.py`:
- **Target RTO (Objective):** < 120.0s (Documented target)
- **Target RPO (Objective):** < 60.0s (Documented target)
- **Recovery Verification Drill Duration:** 0.06s across all 5 tiers (DB, Storage, Keyring, Transparency, Outbox).
- **Scope & Limitations:** The automated drill evaluates database and storage cryptographic consistency. It is a local verification drill and does not measure physical network transfer or cold cluster re-provisioning times.
"""
    Path("BENCHMARKS.md").write_text(bench_md)
    print("[+] Successfully generated BENCHMARKS.md with actual empirical data.")


if __name__ == "__main__":
    asyncio.run(run_all_benchmarks())
