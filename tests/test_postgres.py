import os

import pytest

from agent_safety_lab import (
    Action,
    ActionContext,
    ActionFirewall,
    Environment,
    PolicyEngine,
    PolicyRule,
    PolicySet,
    ToolAction,
)
from agent_safety_lab.audit_store import SqlAuditStore

POSTGRES_URL = os.getenv("ASL_TEST_POSTGRES_URL")


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
