from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from execuseal import (
    Action,
    ActionContext,
    ActionDecision,
    ActionFirewall,
    Environment,
    PolicyEngine,
    PolicyRule,
    PolicySet,
    ToolAction,
)
from execuseal.audit_store import SqlAuditStore, audit_events
from execuseal.checkpoints import (
    AuditCheckpoint,
    CheckpointError,
    create_checkpoint,
    verify_checkpoint,
)


def populated_store(
    path: Path,
) -> tuple[SqlAuditStore, ToolAction, ActionContext, ActionDecision]:
    store = SqlAuditStore(f"sqlite:///{path}")
    store.initialize()
    action = ToolAction("db", "read", "inventory")
    context = ActionContext("agent", "operator", Environment.PRODUCTION)
    firewall = ActionFirewall(PolicyEngine(PolicySet((PolicyRule("allow", Action.ALLOW),))))
    decision = firewall.authorize(action, context)
    store.append("event-1", action, context, decision)
    return store, action, context, decision


def test_checkpoint_survives_later_append_and_round_trip(tmp_path: Path) -> None:
    store, action, context, decision = populated_store(tmp_path / "audit.db")
    private = Ed25519PrivateKey.generate()
    checkpoint = create_checkpoint(
        store,
        private,
        "audit-2026-09",
        datetime(2026, 9, 12, tzinfo=UTC),
    )
    store.append("event-2", action, context, decision)

    restored = AuditCheckpoint.from_json(checkpoint.to_json())
    verify_checkpoint(restored, {"audit-2026-09": private.public_key()}, store)
    assert restored.record_count == 1


def test_checkpoint_detects_signature_tampering_and_database_rollback(tmp_path: Path) -> None:
    store, _action, _context, _decision = populated_store(tmp_path / "audit.db")
    private = Ed25519PrivateKey.generate()
    checkpoint = create_checkpoint(store, private, "audit-key")
    tampered = AuditCheckpoint(
        checkpoint.version,
        checkpoint.algorithm,
        checkpoint.key_id,
        checkpoint.created_at,
        checkpoint.record_count,
        "f" * 64,
        checkpoint.signature,
    )
    with pytest.raises(CheckpointError, match="signature"):
        verify_checkpoint(tampered, {"audit-key": private.public_key()}, store)

    with store.engine.begin() as connection:
        connection.execute(audit_events.delete())
    with pytest.raises(CheckpointError, match="rolled back"):
        verify_checkpoint(checkpoint, {"audit-key": private.public_key()}, store)


def test_checkpoint_rejects_unknown_key_and_invalid_document(tmp_path: Path) -> None:
    store, _action, _context, _decision = populated_store(tmp_path / "audit.db")
    checkpoint = create_checkpoint(store, Ed25519PrivateKey.generate(), "audit-key")
    with pytest.raises(CheckpointError, match="unknown"):
        verify_checkpoint(checkpoint, {}, store)
    with pytest.raises(CheckpointError, match="document"):
        AuditCheckpoint.from_json("not-json")
