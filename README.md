# Agent Safety Lab

**Stop unsafe AI agents before they act.**

Agent Safety Lab is an open-source action firewall and continuous safety-testing
platform for AI agents. It evaluates proposed tool actions, enforces explicit
authorization policy, estimates blast radius, and produces verifiable audit
evidence before an agent can affect external systems.

> **Status:** pre-alpha. The current detector is an explainable baseline, not a
> complete security boundary.

## Why this is different

Most guardrails inspect what a model says. Agent Safety Lab controls what an
agent may **do** across databases, APIs, files, email, browsers, and MCP tools.

- enforcement happens outside the LLM and before tool execution
- policy is deterministic, explicit, and default-deny
- critical blast radius can require approval even when policy allows an action
- audit records are hash-chained and exclude prompts and tool parameters
- the core is model- and provider-independent

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
pytest
```

```python
from agent_safety_lab import (
    Action, ActionContext, ActionFirewall, Environment,
    PolicyEngine, PolicyRule, PolicySet, ToolAction,
)

policy = PolicySet((
    PolicyRule(
        "allow-inventory-read",
        Action.ALLOW,
        tools=frozenset({"inventory_db"}),
        operations=frozenset({"read"}),
        resources=frozenset({"stock_levels"}),
    ),
))
firewall = ActionFirewall(PolicyEngine(policy))
decision = firewall.authorize(
    ToolAction("inventory_db", "read", "stock_levels"),
    ActionContext("warehouse-agent", "operator-42", Environment.PRODUCTION),
)
print(decision.action, decision.blast_radius)
```

See [`examples/warehouse_agent.py`](examples/warehouse_agent.py) for a concrete
operational-agent example.

## Design principles

1. Default to deterministic, testable, default-deny controls for enforcement.
2. Explain every decision with stable rule identifiers.
3. Separate detection, risk scoring, and policy enforcement.
4. Minimize collection of prompt content and sensitive data.
5. Never claim that a passing result makes an AI system safe.

## Current capabilities

- tool, operation, resource, environment, data-classification, and impact rules
- `allow`, `review`, and `block` enforcement decisions
- automatic approval requirement for critical blast radius
- explainable blast-radius scoring
- privacy-aware SHA-256 audit hash chains
- baseline prompt-risk detection

## Important limitation

This project is pre-alpha. Hash chaining makes later modification detectable;
it does not by itself prevent deletion, rollback, or replacement of the entire
audit log. Production use will require signed checkpoints and durable external
storage.

See [THREAT_MODEL.md](THREAT_MODEL.md), [ARCHITECTURE.md](ARCHITECTURE.md), and
[ROADMAP.md](ROADMAP.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
