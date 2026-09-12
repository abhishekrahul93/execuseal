"""Portable Ed25519-signed checkpoints for external audit-log integrity."""

import base64
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from execuseal.audit_store import SqlAuditStore


class CheckpointError(ValueError):
    """Raised when checkpoint evidence cannot be trusted."""


@dataclass(frozen=True, slots=True)
class AuditCheckpoint:
    version: int
    algorithm: str
    key_id: str
    created_at: str
    record_count: int
    chain_head: str
    signature: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, value: str) -> "AuditCheckpoint":
        try:
            raw = json.loads(value)
            checkpoint = cls(**raw)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise CheckpointError("invalid checkpoint document") from error
        if checkpoint.version != 1 or checkpoint.algorithm != "Ed25519":
            raise CheckpointError("unsupported checkpoint version or algorithm")
        if checkpoint.record_count < 0 or len(checkpoint.chain_head) != 64:
            raise CheckpointError("invalid checkpoint claims")
        return checkpoint


def create_checkpoint(
    store: SqlAuditStore,
    private_key: Ed25519PrivateKey,
    key_id: str,
    now: datetime | None = None,
) -> AuditCheckpoint:
    count, head = store.checkpoint_target()
    created_at = (now or datetime.now(UTC)).astimezone(UTC).isoformat()
    claims = _claims(1, "Ed25519", key_id, created_at, count, head)
    signature = _encode(private_key.sign(claims))
    return AuditCheckpoint(1, "Ed25519", key_id, created_at, count, head, signature)


def verify_checkpoint(
    checkpoint: AuditCheckpoint,
    public_keys: dict[str, Ed25519PublicKey],
    store: SqlAuditStore,
) -> None:
    public_key = public_keys.get(checkpoint.key_id)
    if public_key is None:
        raise CheckpointError("unknown checkpoint signing key")
    claims = _claims(
        checkpoint.version,
        checkpoint.algorithm,
        checkpoint.key_id,
        checkpoint.created_at,
        checkpoint.record_count,
        checkpoint.chain_head,
    )
    try:
        public_key.verify(_decode(checkpoint.signature), claims)
    except (InvalidSignature, ValueError) as error:
        raise CheckpointError("invalid checkpoint signature") from error
    if not store.verify():
        raise CheckpointError("current audit chain is invalid")
    current_count, _current_head = store.checkpoint_target()
    if current_count < checkpoint.record_count:
        raise CheckpointError("audit log was rolled back before the checkpoint")
    actual = store.record_hash_at(checkpoint.record_count)
    if actual != checkpoint.chain_head:
        raise CheckpointError("audit history does not match the checkpoint")


def _claims(
    version: int,
    algorithm: str,
    key_id: str,
    created_at: str,
    record_count: int,
    chain_head: str,
) -> bytes:
    return json.dumps(
        {
            "algorithm": algorithm,
            "chain_head": chain_head,
            "created_at": created_at,
            "key_id": key_id,
            "record_count": record_count,
            "version": version,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
