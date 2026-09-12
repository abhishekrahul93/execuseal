import os
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from execuseal import (
    Action,
    ActionContext,
    ActionFirewall,
    Environment,
    PolicyEngine,
    PolicyRule,
    PolicySet,
    ToolAction,
)
from execuseal.audit_store import SqlAuditStore
from execuseal.identities import SqlIdentityStore
from execuseal.migrations import require_current, upgrade
from execuseal.tokens import AuthorizationSigner, SqlReplayGuard, TokenError

POSTGRES_URL = os.getenv("EXECUSEAL_TEST_POSTGRES_URL")


@pytest.mark.skipif(not POSTGRES_URL, reason="PostgreSQL integration URL not configured")
def test_postgresql_audit_round_trip() -> None:
    assert POSTGRES_URL is not None
    store = SqlAuditStore(POSTGRES_URL)
    store.initialize()
    action = ToolAction("db", "read", "inventory")
    context = ActionContext("agent", "operator", Environment.STAGING)
    firewall = ActionFirewall(PolicyEngine(PolicySet((PolicyRule("allow", Action.ALLOW),))))

    store.append("postgres-event-1", action, context, firewall.authorize(action, context))

    assert store.count() == 1
    assert store.verify()
    store.close()


@pytest.mark.skipif(not POSTGRES_URL, reason="PostgreSQL integration URL not configured")
def test_postgresql_replay_is_rejected_across_verifier_instances() -> None:
    assert POSTGRES_URL is not None
    action = ToolAction("db", "read", f"inventory-{uuid4()}")
    context = ActionContext("agent", "operator", Environment.STAGING)
    private_key = Ed25519PrivateKey.generate()
    first_guard = SqlReplayGuard(POSTGRES_URL)
    first_guard.initialize()
    first = AuthorizationSigner({"integration": private_key}, "integration", first_guard)
    token = first.issue(action, context, Action.ALLOW, now=100)
    first.verify_and_consume(token, action, context, now=101)

    second_guard = SqlReplayGuard(POSTGRES_URL)
    second_guard.initialize()
    second = AuthorizationSigner({"integration": private_key}, "integration", second_guard)
    with pytest.raises(TokenError, match="consumed"):
        second.verify_and_consume(token, action, context, now=102)

    first_guard.close()
    second_guard.close()


@pytest.mark.skipif(not POSTGRES_URL, reason="PostgreSQL integration URL not configured")
def test_postgresql_migration_and_identity_revocation() -> None:
    assert POSTGRES_URL is not None
    upgrade(POSTGRES_URL)
    require_current(POSTGRES_URL)
    store = SqlIdentityStore(POSTGRES_URL)
    principal = f"integration-{uuid4()}"
    issued = store.issue(principal, frozenset({"scan"}), ttl_seconds=60)

    assert store.authenticate(issued.api_key, "scan") is not None
    assert store.authenticate(issued.api_key, "authorize") is None
    assert store.revoke(issued.identity.key_id)
    assert store.authenticate(issued.api_key, "scan") is None
    store.close()
