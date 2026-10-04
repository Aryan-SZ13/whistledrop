from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class MerkleAuditStep(BaseModel):
    direction: str = Field(..., description="Direction of sibling: 'left' or 'right'")
    hash: str = Field(..., description="Hexadecimal SHA-256 hash of the sibling node")


class MerkleReceipt(BaseModel):
    leaf_index: int = Field(..., description="Contiguous leaf index of the committed event")
    tree_size: int = Field(..., description="Tree size at commitment time")
    leaf_hash: str = Field(..., description="RFC 6962 leaf hash")
    root_hash: Optional[str] = Field(default=None, description="Root hash of the current tree head")
    sth_signature: Optional[str] = Field(default=None, description="Ed25519 signature on the signed tree head")
    signing_key_id: Optional[str] = Field(default=None, description="Identifier of the Ed25519 platform signing key")

    model_config = ConfigDict(from_attributes=True)


class SignedTreeHeadResponse(BaseModel):
    tree_size: int = Field(..., description="Number of leaves in this tree snapshot")
    root_hash: str = Field(..., description="Root SHA-256 hash of the Merkle Tree")
    signature: str = Field(..., description="Hexadecimal Ed25519 digital signature")
    signing_key_id: str = Field(..., description="Signing key identifier")
    created_at: datetime = Field(..., description="Timestamp when this tree head was signed")

    model_config = ConfigDict(from_attributes=True)


class InclusionProofResponse(BaseModel):
    leaf_index: int = Field(..., description="Leaf index being proven")
    tree_size: int = Field(..., description="Tree size within which inclusion is proven")
    leaf_hash: str = Field(..., description="RFC 6962 leaf hash")
    audit_path: List[MerkleAuditStep] = Field(..., description="List of sibling nodes to root")

    model_config = ConfigDict(from_attributes=True)


class ConsistencyProofResponse(BaseModel):
    first_tree_size: int = Field(..., description="Older tree size")
    second_tree_size: int = Field(..., description="Newer tree size")
    consistency_path: List[str] = Field(..., description="Hashes establishing append-only consistency")

    model_config = ConfigDict(from_attributes=True)
