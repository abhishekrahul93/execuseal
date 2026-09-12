from dataclasses import replace
from datetime import UTC, datetime

from execuseal import (
    Action,
    ActionContext,
    ActionFirewall,
    AuditChain,
    Environment,
    PolicyEngine,
    PolicyRule,
    PolicySet,
    ToolAction,
)


def test_audit_chain_is_verifiable_and_excludes_parameters() -> None:
    firewall = ActionFirewall(
        PolicyEngine(PolicySet((PolicyRule("allow-read", Action.ALLOW),)))
    )
    context = ActionContext("agent-1", "user-1", Environment.DEVELOPMENT)
    action = ToolAction("db", "read", "orders", parameters={"secret": "do-not-store"})
    decision = firewall.authorize(action, context)
    chain = AuditChain()

    record = chain.append(
        "event-1",
        action,
        context,
        decision,
        datetime(2026, 9, 12, 18, 30, tzinfo=UTC),
    )

    assert chain.verify()
    assert record.previous_hash == "GENESIS"
    assert "do-not-store" not in repr(record)


def test_audit_chain_detects_tampering() -> None:
    firewall = ActionFirewall(
        PolicyEngine(PolicySet((PolicyRule("allow-read", Action.ALLOW),)))
    )
    context = ActionContext("agent-1", "user-1", Environment.DEVELOPMENT)
    action = ToolAction("db", "read", "orders")
    decision = firewall.authorize(action, context)
    chain = AuditChain()
    chain.append("event-1", action, context, decision)
    original = chain._records[0]  # Deliberate corruption simulates storage tampering.
    chain._records[0] = replace(original, decision="block")

    assert not chain.verify()
