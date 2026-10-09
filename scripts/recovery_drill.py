#!/usr/bin/env python3
"""
WhistleDrop Automated Recovery Drill Execution Tool
Executes an end-to-end non-destructive disaster recovery exercise:
generates snapshot manifests, runs cryptographic integrity checks,
reconciles evidence, checks outbox recovery, and computes RPO/RTO metrics.
"""
import asyncio
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.session import async_session_factory
from app.services.recovery_service import recovery_service
from scripts.backup_verify import verify_backup


async def run_recovery_drill() -> int:
    print("================================================================================")
    print("WHISTLEDROP DISASTER RECOVERY DRILL — EXERCISE SIMULATION")
    print("================================================================================")
    start_time = time.time()

    drill_dir = Path("./backup_snapshots/drill_test")
    drill_dir.mkdir(parents=True, exist_ok=True)

    print("\n[STEP 1] Generating cryptographic backup manifest and dependency graph snapshot...")
    async with async_session_factory() as session:
        manifest = await recovery_service.generate_backup_manifest(session, drill_dir)

    print(f"  [+] Backup Manifest Generated:")
    print(f"      - Merkle Root: {manifest['merkle_root_hash']}")
    print(f"      - Merkle Tree Size: {manifest['merkle_tree_size']}")
    print(f"      - Evidence Files Bound: {manifest['evidence_files_count']}")
    print(f"      - Required KEK Versions: {manifest['required_kek_versions']}")

    print("\n[STEP 2] Verifying backup archive integrity and SHA-256 digests...")
    verify_exit_code = verify_backup(drill_dir)
    if verify_exit_code != 0:
        print("[!] STEP 2 FAILED: Manifest digest validation failed.")
        return 1

    print("\n[STEP 3] Auditing restored state and verifying live cryptographic consistency...")
    async with async_session_factory() as session:
        report = await recovery_service.run_full_recovery_audit(session)

    elapsed = round(time.time() - start_time, 2)

    print("\n================================================================================")
    print("RECOVERY DRILL SUMMARY & CONTINUITY METRICS")
    print("================================================================================")
    print(f"Drill Verification Duration: {elapsed}s")
    print(f"Target RTO (Objective):      {report.rto_estimated_seconds}s")
    print(f"Target RPO (Objective):      {report.rpo_estimated_seconds}s")
    print(f"Keyring Validation:          {'PASSED' if report.keyring_check.is_valid else 'FAILED'}")
    print(f"Storage Consistency:         {'PASSED' if report.storage_check.is_consistent else 'FAILED'}")
    print(f"Transparency Consistency:    {'PASSED' if report.transparency_check.is_consistent else 'FAILED'}")
    print(f"Transactional Outbox:        {'PASSED' if report.outbox_check.failed_dead_letter_count == 0 else 'DEGRADED'}")
    print(f"Overall Recovery Status:     {report.status}")
    print("================================================================================")

    if report.status == "CRITICAL_DRIFT":
        print("\n[!] DRILL FAILED: Critical drift detected in restored instance.")
        return 1

    print("\n[+] DRILL PASSED: System is verifiable, recoverable, and business-continuity compliant.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(run_recovery_drill()))
