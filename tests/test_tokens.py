import pytest

from agent_safety_lab import Action, ActionContext, Environment, ToolAction
from agent_safety_lab.tokens import AuthorizationSigner, TokenError

SECRET = "test-signing-secret-with-more-than-32-bytes"


def action_and_context() -> tuple[ToolAction, ActionContext]:
    return (
        ToolAction("inventory.read", "read", "stock_levels", parameters={"sku": "A-1"}),
        ActionContext("warehouse-agent", "operator-42", Environment.PRODUCTION),
    )


def test_token_is_bound_to_action_and_single_use() -> None:
    action, context = action_and_context()
    signer = AuthorizationSigner(SECRET, ttl_seconds=30)
    token = signer.issue(action, context, Action.ALLOW, now=100)

    claims = signer.verify_and_consume(token, action, context, now=101)

    assert claims.action == "allow"
    with pytest.raises(TokenError, match="consumed"):
        signer.verify_and_consume(token, action, context, now=102)


def test_rejects_tampering_expiry_and_action_substitution() -> None:
    action, context = action_and_context()
    signer = AuthorizationSigner(SECRET, ttl_seconds=10)

    token = signer.issue(action, context, Action.ALLOW, now=100)
    with pytest.raises(TokenError, match="signature"):
        signer.verify_and_consume(token + "x", action, context, now=101)

    token = signer.issue(action, context, Action.ALLOW, now=100)
    changed = ToolAction("inventory.read", "read", "stock_levels", parameters={"sku": "B-2"})
    with pytest.raises(TokenError, match="does not match"):
        signer.verify_and_consume(token, changed, context, now=101)

    token = signer.issue(action, context, Action.ALLOW, now=100)
    with pytest.raises(TokenError, match="expired"):
        signer.verify_and_consume(token, action, context, now=110)


def test_refuses_tokens_for_non_allowed_decisions() -> None:
    action, context = action_and_context()
    signer = AuthorizationSigner(SECRET)

    with pytest.raises(TokenError, match="only allowed"):
        signer.issue(action, context, Action.BLOCK)


@pytest.mark.parametrize("secret", ["short", ""])
def test_requires_strong_signing_secret(secret: str) -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        AuthorizationSigner(secret)
