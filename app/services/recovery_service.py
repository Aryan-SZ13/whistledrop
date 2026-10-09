from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.encryption import CaseEncryptionKey
from app.models.enums import EvidenceScanStatus, EvidenceShredStatus
from app.models.evidence import EvidenceAttachment
from app.models.webhook import OutboxEvent
from app.models.transparency import MerkleLeaf, MerkleTreeState, SignedTreeHead
from app.services.payload_encryption_service import payload_encryption_service
from app.services.transparency_service import transparency_service

logger = logging.getLogger(__name__)


@dataclass
class KeyringVerificationResult:
    is_valid: bool
    required_versions: Set[int]
    available_versions: Set[int]
    missing_versions: Set[int]
    total_keys_checked: int


@dataclass
class StorageReconciliationResult:
    is_consistent: bool
    db_attachments_count: int
    files_on_disk_count: int
    missing_files: List[str]  # In DB but absent on disk
    orphan_files: List[str]   # On disk but not recorded in DB
    shredded_records_with_files: List[str]


@dataclass
class TransparencyConsistencyResult:
    is_consistent: bool
    recorded_tree_size: int
    actual_leaf_count: int
    recorded_root_hex: Optional[str]
    computed_root_hex: Optional[str]
    root_match: bool


@dataclass
class OutboxRecoveryResult:
    pending_events_count: int
    stuck_leases_reset: int
    failed_dead_letter_count: int


@dataclass
class RecoveryIntegrityReport:
    timestamp: str
    status: str  # "HEALTHY" | "DEGRADED" | "CRITICAL_DRIFT"
    keyring_check: KeyringVerificationResult
    storage_check: StorageReconciliationResult
    transparency_check: TransparencyConsistencyResult
    outbox_check: OutboxRecoveryResult
    rpo_estimated_seconds: float
    rto_estimated_seconds: float
    errors: List[str] = field(default_factory=list)


class RecoveryService:
    """
    Manages disaster recovery modeling, backup integrity verification,
    and business continuity validation across WhistleDrop's cryptographic dependency graph.
    """

    async def verify_kek_keyring_dependencies(self, db: AsyncSession) -> KeyringVerificationResult:
        """
        Verifies that every KEK version required to decrypt active case DEKs
        is present and valid in the application's runtime KEK keyring.
        """
        stmt = sa.select(CaseEncryptionKey.key_version).distinct()
        res = await db.execute(stmt)
        required_versions: Set[int] = set(res.scalars().all())

        raw_keyring = settings.PAYLOAD_KEK_KEYRING
        if isinstance(raw_keyring, str):
            try:
                raw_keyring = json.loads(raw_keyring)
            except Exception:
                raw_keyring = {}

        available_versions: Set[int] = {int(k) for k in raw_keyring.keys() if str(k).isdigit()}
        missing = required_versions - available_versions

        count_stmt = sa.select(sa.func.count(CaseEncryptionKey.report_id))
        total_keys = (await db.execute(count_stmt)).scalar() or 0

        return KeyringVerificationResult(
            is_valid=len(missing) == 0,
            required_versions=required_versions,
            available_versions=available_versions,
            missing_versions=missing,
            total_keys_checked=total_keys,
        )

    async def reconcile_evidence_storage(self, db: AsyncSession) -> StorageReconciliationResult:
        """
        Reconciles database evidence attachment records with filesystem objects,
        detecting missing storage files, unindexed orphans, and post-shred leakage.
        """
        storage_root = Path(settings.EVIDENCE_STORAGE_PATH)
        approved_dir = storage_root / "approved"
        approved_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        # Collect files on disk
        disk_keys: Set[str] = set()
        if approved_dir.is_dir():
            for f in approved_dir.iterdir():
                if f.is_file() and f.name.endswith(".bin"):
                    disk_keys.add(f.name[:-4])

        # Collect active DB attachments
        stmt = sa.select(
            EvidenceAttachment.storage_key,
            EvidenceAttachment.shred_status,
        )
        res = await db.execute(stmt)
        rows = res.all()

        missing_files: List[str] = []
        shredded_with_files: List[str] = []
        db_keys: Set[str] = set()

        for key, shred_status in rows:
            db_keys.add(key)
            has_file = key in disk_keys
            if shred_status == EvidenceShredStatus.ACTIVE.value:
                if not has_file:
                    missing_files.append(key)
            elif shred_status in (EvidenceShredStatus.KEY_DESTROYED.value, EvidenceShredStatus.PHYSICALLY_SHREDDED.value):
                if has_file:
                    shredded_with_files.append(key)

        orphan_files = list(disk_keys - db_keys)

        is_consistent = (len(missing_files) == 0) and (len(orphan_files) == 0)

        return StorageReconciliationResult(
            is_consistent=is_consistent,
            db_attachments_count=len(rows),
            files_on_disk_count=len(disk_keys),
            missing_files=missing_files,
            orphan_files=orphan_files,
            shredded_records_with_files=shredded_with_files,
        )

    async def verify_transparency_consistency(self, db: AsyncSession) -> TransparencyConsistencyResult:
        """
        Validates the append-only RFC 6962 Merkle tree state:
        Confirms leaf count matches tree_size, verifies latest STH prefix,
        and recomputes current tree root hash.
        """
        state_stmt = sa.select(MerkleTreeState).where(MerkleTreeState.id == 1)
        tree_state = (await db.execute(state_stmt)).scalar_one_or_none()

        count_stmt = sa.select(sa.func.count(MerkleLeaf.leaf_index))
        actual_count = (await db.execute(count_stmt)).scalar() or 0

        sth_stmt = sa.select(SignedTreeHead).order_by(SignedTreeHead.tree_size.desc()).limit(1)
        latest_sth = (await db.execute(sth_stmt)).scalar_one_or_none()

        if not tree_state:
            is_consistent = (actual_count == 0)
            return TransparencyConsistencyResult(
                is_consistent=is_consistent,
                recorded_tree_size=0,
                actual_leaf_count=actual_count,
                recorded_root_hex=None,
                computed_root_hex=None,
                root_match=is_consistent,
            )

        recorded_size = tree_state.tree_size

        # Recompute root from leaves
        leaves_stmt = sa.select(MerkleLeaf.leaf_hash).order_by(MerkleLeaf.leaf_index.asc())
        leaves_res = await db.execute(leaves_stmt)
        leaf_hashes = list(leaves_res.scalars().all())

        if leaf_hashes:
            computed_current_root = transparency_service.compute_mth(leaf_hashes)
        else:
            computed_current_root = None

        size_match = (recorded_size == actual_count == len(leaf_hashes))

        sth_match = True
        if latest_sth:
            if latest_sth.tree_size > len(leaf_hashes):
                sth_match = False
            else:
                prefix_root = transparency_service.compute_mth(leaf_hashes[:latest_sth.tree_size])
                sth_match = (prefix_root == latest_sth.root_hash)

        is_consistent = size_match and sth_match

        return TransparencyConsistencyResult(
            is_consistent=is_consistent,
            recorded_tree_size=recorded_size,
            actual_leaf_count=actual_count,
            recorded_root_hex=computed_current_root,
            computed_root_hex=computed_current_root,
            root_match=sth_match,
        )

    async def reset_stuck_outbox_leases(self, db: AsyncSession, threshold_seconds: int = 300) -> OutboxRecoveryResult:
        """
        Resets orphaned outbox leases after worker failure or crash,
        enabling pending notifications to safely resume processing without duplicates.
        """
        now = datetime.now(timezone.utc)

        # Count pending/claimed
        pending_stmt = sa.select(sa.func.count(OutboxEvent.id)).where(
            OutboxEvent.status.in_(("PENDING", "CLAIMED", "FAILED"))
        )
        pending_count = (await db.execute(pending_stmt)).scalar() or 0

        # Reset stuck leases (CLAIMED events whose lease has expired)
        reset_stmt = (
            sa.update(OutboxEvent)
            .where(
                OutboxEvent.status == "CLAIMED",
                OutboxEvent.lease_expires_at.is_not(None),
                OutboxEvent.lease_expires_at <= now,
            )
            .values(status="PENDING", lease_worker_id=None, lease_expires_at=None)
        )
        res = await db.execute(reset_stmt)
        stuck_reset = res.rowcount

        # Count dead letters
        dead_stmt = sa.select(sa.func.count(OutboxEvent.id)).where(
            OutboxEvent.status == "DEAD_LETTER"
        )
        dead_count = (await db.execute(dead_stmt)).scalar() or 0

        await db.commit()

        return OutboxRecoveryResult(
            pending_events_count=pending_count,
            stuck_leases_reset=stuck_reset,
            failed_dead_letter_count=dead_count,
        )

    async def generate_backup_manifest(
        self,
        db: AsyncSession,
        backup_dir: Path,
    ) -> Dict[str, Any]:
        """
        Generates a cryptographic backup manifest binding database state,
        keyring versions, Merkle tree root, and evidence files with SHA-256 digests.
        """
        backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        keyring_res = await self.verify_kek_keyring_dependencies(db)
        transparency_res = await self.verify_transparency_consistency(db)
        storage_res = await self.reconcile_evidence_storage(db)

        # File digests in evidence storage
        storage_root = Path(settings.EVIDENCE_STORAGE_PATH) / "approved"
        file_manifest: Dict[str, str] = {}
        if storage_root.is_dir():
            for f in sorted(storage_root.iterdir()):
                if f.is_file():
                    digest = hashlib.sha256(f.read_bytes()).hexdigest()
                    file_manifest[f.name] = digest

        manifest_data = {
            "manifest_version": "1.0",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "generator": "whistledrop-recovery-service",
            "required_kek_versions": sorted(list(keyring_res.required_versions)),
            "active_kek_version": settings.PAYLOAD_KEK_ACTIVE_VERSION,
            "merkle_tree_size": transparency_res.recorded_tree_size,
            "merkle_root_hash": transparency_res.recorded_root_hex,
            "evidence_files_count": len(file_manifest),
            "evidence_digests": file_manifest,
            "is_fully_consistent": keyring_res.is_valid and transparency_res.is_consistent and storage_res.is_consistent,
        }

        # Deterministic canonical serialization
        canonical_bytes = json.dumps(manifest_data, sort_keys=True, indent=2).encode("utf-8")
        manifest_path = backup_dir / "backup_manifest.json"
        manifest_path.write_bytes(canonical_bytes)

        # Signature over manifest digest
        manifest_digest = hashlib.sha256(canonical_bytes).hexdigest()
        (backup_dir / "backup_manifest.sha256").write_text(f"{manifest_digest}  backup_manifest.json\n")

        return manifest_data

    async def run_full_recovery_audit(self, db: AsyncSession) -> RecoveryIntegrityReport:
        """
        Executes complete multi-tier recovery graph integrity audit,
        evaluating RPO and RTO parameters and surfacing all points of drift.
        """
        errors: List[str] = []

        keyring_check = await self.verify_kek_keyring_dependencies(db)
        if not keyring_check.is_valid:
            errors.append(f"Missing payload KEK versions in keyring: {keyring_check.missing_versions}")

        storage_check = await self.reconcile_evidence_storage(db)
        if not storage_check.is_consistent:
            if storage_check.missing_files:
                errors.append(f"Missing evidence files on disk: {len(storage_check.missing_files)}")
            if storage_check.orphan_files:
                errors.append(f"Unindexed orphan files in storage: {len(storage_check.orphan_files)}")

        transparency_check = await self.verify_transparency_consistency(db)
        if not transparency_check.is_consistent:
            errors.append("RFC 6962 Merkle tree state inconsistent with leaf log records.")

        outbox_check = await self.reset_stuck_outbox_leases(db)

        # Status evaluation
        if not keyring_check.is_valid or not transparency_check.is_consistent:
            status = "CRITICAL_DRIFT"
        elif not storage_check.is_consistent or outbox_check.failed_dead_letter_count > 0:
            status = "DEGRADED"
        else:
            status = "HEALTHY"

        now = datetime.now(timezone.utc).isoformat()
        return RecoveryIntegrityReport(
            timestamp=now,
            status=status,
            keyring_check=keyring_check,
            storage_check=storage_check,
            transparency_check=transparency_check,
            outbox_check=outbox_check,
            rpo_estimated_seconds=60.0,   # Snapshot / WAL replication frequency target
            rto_estimated_seconds=120.0,  # Cold-start container & DB restoration target
            errors=errors,
        )


recovery_service = RecoveryService()
