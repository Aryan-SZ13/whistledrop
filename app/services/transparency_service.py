from datetime import datetime, timezone
import hashlib
import logging
from typing import Any, Dict, List, Optional, Tuple
import uuid

from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import HTTPException, status
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.transparency import MerkleLeaf, MerkleTreeState, SignedTreeHead

logger = logging.getLogger(__name__)


class TransparencyService:
    """RFC 6962-compliant Append-Only Merkle Transparency Log Service."""

    def __init__(self) -> None:
        self.signing_key_id = settings.TRANSPARENCY_STH_SIGNING_KEY_ID

    def _get_signing_key(self) -> ed25519.Ed25519PrivateKey:
        raw_key = settings.EXPORT_SIGNING_KEY_ED25519_PRIVATE
        try:
            seed = bytes.fromhex(raw_key)
        except ValueError:
            seed = raw_key.encode("utf-8")[:32].ljust(32, b"\x00")
        return ed25519.Ed25519PrivateKey.from_private_bytes(seed)

    def get_public_key_fingerprint(self) -> str:
        priv = self._get_signing_key()
        pub_bytes = priv.public_key().public_bytes_raw()
        return f"SHA256:{hashlib.sha256(pub_bytes).hexdigest()}"

    def compute_canonical_leaf_bytes(
        self,
        event_type: str,
        opaque_reference: str,
        occurred_at: datetime,
        payload_digest: bytes,
    ) -> bytes:
        """Deterministic, versioned, length-prefixed binary canonical leaf bytes."""
        event_type_bytes = event_type.encode("utf-8")
        opaque_ref_bytes = opaque_reference.encode("utf-8")
        ts_int = int(occurred_at.timestamp())

        return (
            b"\x01"  # Version 1
            + len(event_type_bytes).to_bytes(2, "big")
            + event_type_bytes
            + len(opaque_ref_bytes).to_bytes(2, "big")
            + opaque_ref_bytes
            + ts_int.to_bytes(8, "big")
            + payload_digest
        )

    def compute_leaf_hash(self, canonical_bytes: bytes) -> str:
        """RFC 6962 §2.1: leaf_hash = SHA-256(0x00 || canonical_leaf_bytes)."""
        return hashlib.sha256(b"\x00" + canonical_bytes).hexdigest()

    def compute_node_hash(self, left_hex: str, right_hex: str) -> str:
        """RFC 6962 §2.1: node_hash = SHA-256(0x01 || left || right)."""
        return hashlib.sha256(b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)).hexdigest()

    def compute_mth(self, leaf_hashes: List[str]) -> str:
        """RFC 6962 Merkle Tree Hash (MTH) calculation over an array of leaf hashes."""
        n = len(leaf_hashes)
        if n == 0:
            return hashlib.sha256(b"").hexdigest()
        if n == 1:
            return leaf_hashes[0]

        # Largest power of 2 strictly less than n
        k = 1 << ((n - 1).bit_length() - 1)
        left_mth = self.compute_mth(leaf_hashes[:k])
        right_mth = self.compute_mth(leaf_hashes[k:])
        return self.compute_node_hash(left_mth, right_mth)

    def compute_audit_path(self, m: int, leaf_hashes: List[str]) -> List[Dict[str, str]]:
        """RFC 6962 §2.1.1 Inclusion Proof PATH(m, D)."""
        n = len(leaf_hashes)
        if n <= 1:
            return []

        k = 1 << ((n - 1).bit_length() - 1)
        if m < k:
            right_hash = self.compute_mth(leaf_hashes[k:])
            return self.compute_audit_path(m, leaf_hashes[:k]) + [{"direction": "right", "hash": right_hash}]
        else:
            left_hash = self.compute_mth(leaf_hashes[:k])
            return self.compute_audit_path(m - k, leaf_hashes[k:]) + [{"direction": "left", "hash": left_hash}]

    def compute_consistency_path(self, m: int, leaf_hashes: List[str]) -> List[str]:
        """RFC 6962 §2.1.2 Consistency Proof PROOF(m, D)."""
        def _sub_proof(m_sub: int, d_sub: List[str], b_flag: bool) -> List[str]:
            n_sub = len(d_sub)
            if m_sub == n_sub:
                if b_flag:
                    return []
                return [self.compute_mth(d_sub)]

            k_sub = 1 << ((n_sub - 1).bit_length() - 1)
            if m_sub <= k_sub:
                return _sub_proof(m_sub, d_sub[:k_sub], b_flag) + [self.compute_mth(d_sub[k_sub:])]
            else:
                return _sub_proof(m_sub - k_sub, d_sub[k_sub:], False) + [self.compute_mth(d_sub[:k_sub])]

        return _sub_proof(m, leaf_hashes, True)

    async def commit_merkle_leaf(
        self,
        db: AsyncSession,
        event_type: str,
        opaque_reference: str,
        payload_digest: bytes,
        occurred_at: Optional[datetime] = None,
    ) -> Tuple[MerkleLeaf, int]:
        """
        Atomically allocates a contiguous index and commits an immutable leaf in the business transaction.
        """
        if occurred_at is None:
            occurred_at = datetime.now(timezone.utc)

        # Ensure singleton state row exists with concurrency safety via INSERT ON CONFLICT DO NOTHING
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        upsert_stmt = (
            pg_insert(MerkleTreeState)
            .values(id=1, tree_size=0, next_leaf_index=0)
            .on_conflict_do_nothing(index_elements=["id"])
        )
        await db.execute(upsert_stmt)

        # Lock singleton state row to allocate contiguous sequence
        stmt_state = sa.select(MerkleTreeState).where(MerkleTreeState.id == 1).with_for_update()
        state = (await db.execute(stmt_state)).scalar_one()

        assigned_index = state.next_leaf_index
        canonical_bytes = self.compute_canonical_leaf_bytes(
            event_type=event_type,
            opaque_reference=opaque_reference,
            occurred_at=occurred_at,
            payload_digest=payload_digest,
        )
        leaf_hash = self.compute_leaf_hash(canonical_bytes)

        leaf = MerkleLeaf(
            leaf_index=assigned_index,
            leaf_hash=leaf_hash,
            event_type=event_type,
            opaque_reference=opaque_reference,
            canonical_leaf_bytes=canonical_bytes,
            created_at=occurred_at,
        )
        db.add(leaf)

        state.next_leaf_index += 1
        state.tree_size += 1
        await db.flush()

        return leaf, state.tree_size

    async def sign_sth(self, db: AsyncSession) -> SignedTreeHead:
        """Asynchronously computes MTH for all committed leaves and generates an Ed25519-signed STH."""
        stmt = sa.select(MerkleLeaf.leaf_hash).order_by(MerkleLeaf.leaf_index.asc())
        res = await db.execute(stmt)
        leaf_hashes = list(res.scalars().all())

        tree_size = len(leaf_hashes)
        root_hash = self.compute_mth(leaf_hashes)
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        canonical_sth_bytes = f"STH:v1:{tree_size}:{root_hash}:{self.signing_key_id}:{now_iso}".encode("utf-8")
        sth_digest = hashlib.sha256(canonical_sth_bytes).digest()

        priv_key = self._get_signing_key()
        sig_bytes = priv_key.sign(sth_digest)
        sig_hex = sig_bytes.hex()

        # Update or insert STH for this tree_size
        stmt_sth = sa.select(SignedTreeHead).where(SignedTreeHead.tree_size == tree_size).with_for_update()
        existing_sth = (await db.execute(stmt_sth)).scalar_one_or_none()
        if existing_sth:
            existing_sth.root_hash = root_hash
            existing_sth.signature = sig_hex
            existing_sth.signing_key_id = self.signing_key_id
            existing_sth.created_at = now
            sth = existing_sth
        else:
            sth = SignedTreeHead(
                id=uuid.uuid4(),
                tree_size=tree_size,
                root_hash=root_hash,
                signature=sig_hex,
                signing_key_id=self.signing_key_id,
                created_at=now,
            )
            db.add(sth)

        await db.commit()
        return sth

    async def get_latest_sth(self, db: AsyncSession) -> SignedTreeHead:
        """Retrieves latest published Signed Tree Head, generating one if not yet recorded."""
        stmt = sa.select(SignedTreeHead).order_by(SignedTreeHead.created_at.desc(), SignedTreeHead.tree_size.desc()).limit(1)
        sth = (await db.execute(stmt)).scalar_one_or_none()
        if sth is None:
            sth = await self.sign_sth(db)
        return sth

    async def get_inclusion_proof(
        self,
        db: AsyncSession,
        leaf_index: int,
        tree_size: int,
    ) -> Dict[str, Any]:
        """Returns RFC 6962 audit path for a given leaf index at tree_size."""
        if leaf_index < 0 or leaf_index >= tree_size:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"leaf_index {leaf_index} out of bounds for tree_size {tree_size}",
            )

        stmt = (
            sa.select(MerkleLeaf.leaf_hash)
            .where(MerkleLeaf.leaf_index < tree_size)
            .order_by(MerkleLeaf.leaf_index.asc())
        )
        res = await db.execute(stmt)
        leaf_hashes = list(res.scalars().all())

        if len(leaf_hashes) < tree_size:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Tree size {tree_size} leaves not fully available",
            )

        audit_path = self.compute_audit_path(leaf_index, leaf_hashes)
        return {
            "leaf_index": leaf_index,
            "tree_size": tree_size,
            "leaf_hash": leaf_hashes[leaf_index],
            "audit_path": audit_path,
        }

    async def get_consistency_proof(
        self,
        db: AsyncSession,
        first_size: int,
        second_size: int,
    ) -> Dict[str, Any]:
        """Returns RFC 6962 consistency proof between first_size and second_size."""
        if first_size < 1 or second_size < first_size:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid sizes: first_size must be >= 1 and <= second_size",
            )

        stmt = (
            sa.select(MerkleLeaf.leaf_hash)
            .where(MerkleLeaf.leaf_index < second_size)
            .order_by(MerkleLeaf.leaf_index.asc())
        )
        res = await db.execute(stmt)
        leaf_hashes = list(res.scalars().all())

        if len(leaf_hashes) < second_size:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Second tree size {second_size} not fully available",
            )

        consistency_path = self.compute_consistency_path(first_size, leaf_hashes)
        return {
            "first_tree_size": first_size,
            "second_tree_size": second_size,
            "consistency_path": consistency_path,
        }

    def verify_inclusion_proof_standalone(
        self,
        leaf_hash: str,
        leaf_index: int,
        tree_size: int,
        audit_path: List[Dict[str, str]],
        root_hash: str,
    ) -> bool:
        """Standalone verification of an inclusion proof against root_hash."""
        current = leaf_hash
        for step in audit_path:
            direction = step["direction"]
            sibling_hash = step["hash"]
            if direction == "left":
                current = self.compute_node_hash(sibling_hash, current)
            elif direction == "right":
                current = self.compute_node_hash(current, sibling_hash)
            else:
                return False
        return current.lower() == root_hash.lower()

    def verify_sth_signature_standalone(
        self,
        tree_size: int,
        root_hash: str,
        signing_key_id: str,
        created_at_iso: str,
        signature_hex: str,
        public_key_bytes: bytes,
    ) -> bool:
        """Standalone verification of an Ed25519 signature on an STH."""
        canonical_sth_bytes = f"STH:v1:{tree_size}:{root_hash}:{signing_key_id}:{created_at_iso}".encode("utf-8")
        sth_digest = hashlib.sha256(canonical_sth_bytes).digest()
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        try:
            pub_key.verify(bytes.fromhex(signature_hex), sth_digest)
            return True
        except Exception:
            return False


transparency_service = TransparencyService()
