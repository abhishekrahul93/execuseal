from pathlib import Path

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
from execuseal.audit_store import SqlAuditStore, audit_events


def test_detects_database_tampering(tmp_path: Path) -> None:
    store = SqlAuditStore(f"sqlite:///{tmp_path / 'audit.db'}")
    store.initialize()
    action = ToolAction("db", "read", "orders")
    context = ActionContext("agent", "person", Environment.DEVELOPMENT)
    firewall = ActionFirewall(PolicyEngine(PolicySet((PolicyRule("allow", Action.ALLOW),))))
    decision = firewall.authorize(action, context)
    store.append("event-1", action, context, decision)

    with store.engine.begin() as connection:
        connection.execute(audit_events.update().values(decision="block"))

    assert not store.verify()
