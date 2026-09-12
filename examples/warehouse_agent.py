"""Minimal operational example: authorize an inventory action before execution."""

from execuseal import (
    Action,
    ActionContext,
    ActionFirewall,
    Environment,
    Impact,
    PolicyEngine,
    PolicyRule,
    PolicySet,
    ToolAction,
)

policy = PolicySet(
    rules=(
        PolicyRule(
            "allow-stock-read",
            Action.ALLOW,
            tools=frozenset({"inventory_db"}),
            operations=frozenset({"read"}),
            resources=frozenset({"stock_levels"}),
        ),
        PolicyRule(
            "review-stock-update",
            Action.REVIEW,
            tools=frozenset({"inventory_db"}),
            operations=frozenset({"update"}),
            maximum_impact=Impact.MULTIPLE_RECORDS,
        ),
    )
)

firewall = ActionFirewall(PolicyEngine(policy))
context = ActionContext("warehouse-copilot", "operator-42", Environment.PRODUCTION)
proposed_action = ToolAction(
    "inventory_db",
    "update",
    "stock_levels",
    impact=Impact.MULTIPLE_RECORDS,
)

decision = firewall.authorize(proposed_action, context)
print(decision)

if decision.execution_allowed:
    print("Tool execution would happen here.")
elif decision.approval_required:
    print("Paused: human approval required.")
else:
    print("Blocked by policy.")
