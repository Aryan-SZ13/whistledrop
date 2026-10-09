#!/usr/bin/env python3
"""
WhistleDrop Restore Verification Tool
Runs live health and cryptographic consistency checks against a restored WhistleDrop instance.
"""
import asyncio
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.session import async_session_factory
from app.services.recovery_service import recovery_service


async def main() -> int:
    print("[*] Initiating WhistleDrop Restore Verification & Dependency Graph Audit...")

    async with async_session_factory() as session:
        report = await recovery_service.run_full_recovery_audit(session)

    print(f"[+] Audit Timestamp: {report.timestamp}")
    print(f"[+] Overall Recovery Status: {report.status}")
    print(f"[+] Estimated RPO: {report.rpo_estimated_seconds}s | Estimated RTO: {report.rto_estimated_seconds}s")
    print(f"[+] Keyring Check: {'PASS' if report.keyring_check.is_valid else 'FAIL'}")
    print(f"    - Required KEK Versions: {report.keyring_check.required_versions}")
    print(f"    - Missing KEK Versions: {report.keyring_check.missing_versions}")
    print(f"[+] Storage Reconciliation: {'PASS' if report.storage_check.is_consistent else 'FAIL'}")
    print(f"    - DB Attachments: {report.storage_check.db_attachments_count}")
    print(f"    - Files on Disk: {report.storage_check.files_on_disk_count}")
    print(f"    - Missing Files: {len(report.storage_check.missing_files)}")
    print(f"    - Orphan Files: {len(report.storage_check.orphan_files)}")
    print(f"[+] Transparency Log Consistency: {'PASS' if report.transparency_check.is_consistent else 'FAIL'}")
    print(f"    - Recorded Tree Size: {report.transparency_check.recorded_tree_size}")
    print(f"    - Actual Leaf Count: {report.transparency_check.actual_leaf_count}")
    print(f"    - Merkle Root Match: {report.transparency_check.root_match}")
    print(f"[+] Transactional Outbox Recovery:")
    print(f"    - Pending Events: {report.outbox_check.pending_events_count}")
    print(f"    - Stuck Leases Reset: {report.outbox_check.stuck_leases_reset}")
    print(f"    - Dead Letters: {report.outbox_check.failed_dead_letter_count}")

    if report.errors:
        print("\n[!] Discovered Recovery Anomalies:")
        for err in report.errors:
            print(f"    - {err}")

    if report.status == "CRITICAL_DRIFT":
        print("\n[!] RESTORE VERIFICATION FAILED (Critical Drift Detected).")
        return 1
    elif report.status == "DEGRADED":
        print("\n[*] RESTORE VERIFICATION COMPLETED WITH WARNINGS (Degraded).")
        return 0
    else:
        print("\n[+] RESTORE VERIFICATION PASSED: Restored instance is cryptographically integral and ready for traffic.")
        return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
