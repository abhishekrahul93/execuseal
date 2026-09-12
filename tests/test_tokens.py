from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from execuseal import Action, ActionContext, Environment, ToolAction
from execuseal.tokens import (
    AuthorizationSigner,
    AuthorizationVerifier,
    SqlReplayGuard,
    TokenError,
)


def action_and_context() -> tuple[ToolAction, ActionContext]:
    return (
        ToolAction("inventory.read", "read", "stock_levels", parameters={"sku": "A-1"}),
        ActionContext("warehouse-agent", "operator-42", Environment.PRODUCTION),
    )


def signer(tmp_path: Path, active: str = "key-2026-09") -> AuthorizationSigner:
    replay = SqlReplayGuard(f"sqlite:///{tmp_path / 'replay.db'}")
    replay.initialize()
    return AuthorizationSigner(
        {
            "key-2026-08": Ed25519PrivateKey.from_private_bytes(b"a" * 32),
            "key-2026-09": Ed25519PrivateKey.from_private_bytes(b"b" * 32),
        },
        active,
        replay,
        ttl_seconds=30,
    )


def test_token_is_bound_to_action_and_durable_single_use(tmp_path: Path) -> None:
    action, context = action_and_context()
    issuer = signer(tmp_path)
    token = issuer.issue(action, context, Action.ALLOW, now=100)

    claims = issuer.verify_and_consume(token, action, context, now=101)

    assert claims.action == "allow"
    assert claims.issuer == "execuseal"
    restarted = signer(tmp_path)
    with pytest.raises(TokenError, match="consumed"):
        restarted.verify_and_consume(token, action, context, now=102)


def test_rejects_tampering_expiry_and_action_substitution(tmp_path: Path) -> None:
    action, context = action_and_context()
    issuer = signer(tmp_path)

    token = issuer.issue(action, context, Action.ALLOW, now=100)
    with pytest.raises(TokenError, match="signature"):
        issuer.verify_and_consume(token + "x", action, context, now=101)

    token = issuer.issue(action, context, Action.ALLOW, now=100)
    changed = ToolAction("inventory.read", "read", "stock_levels", parameters={"sku": "B-2"})
    with pytest.raises(TokenError, match="does not match"):
        issuer.verify_and_consume(token, changed, context, now=101)

    token = issuer.issue(action, context, Action.ALLOW, now=100)
    with pytest.raises(TokenError, match="expired"):
        issuer.verify_and_consume(token, action, context, now=130)


def test_rotation_keeps_old_public_key_without_old_private_key(tmp_path: Path) -> None:
    action, context = action_and_context()
    old_issuer = signer(tmp_path, active="key-2026-08")
    old_token = old_issuer.issue(action, context, Action.ALLOW, now=100)
    public_keys = {
        key_id: key.public_key()
        for key_id, key in {
            "key-2026-08": Ed25519PrivateKey.from_private_bytes(b"a" * 32),
            "key-2026-09": Ed25519PrivateKey.from_private_bytes(b"b" * 32),
        }.items()
    }
    replay = SqlReplayGuard(f"sqlite:///{tmp_path / 'rotated-replay.db'}")
    replay.initialize()
    verifier = AuthorizationVerifier(public_keys, replay)

    assert verifier.verify_and_consume(old_token, action, context, now=101).version == 2
    new_token = signer(tmp_path, active="key-2026-09").issue(
        action, context, Action.ALLOW, now=100
    )
    assert ".key-2026-09." in new_token


def test_refuses_invalid_configuration_and_non_allow_decisions(tmp_path: Path) -> None:
    action, context = action_and_context()
    issuer = signer(tmp_path)
    with pytest.raises(TokenError, match="only allowed"):
        issuer.issue(action, context, Action.BLOCK)
    replay = SqlReplayGuard(f"sqlite:///{tmp_path / 'invalid.db'}")
    replay.initialize()
    with pytest.raises(ValueError, match="active signing key"):
        AuthorizationSigner({}, "missing", replay)
