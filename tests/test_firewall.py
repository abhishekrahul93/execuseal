from execuseal import (
    Action,
    ActionContext,
    ActionFirewall,
    DataClassification,
    Environment,
    Impact,
    PolicyEngine,
    PolicyRule,
    PolicySet,
    ToolAction,
)


def warehouse_firewall() -> ActionFirewall:
    policy = PolicySet(
        rules=(
            PolicyRule(
                rule_id="warehouse-block-export",
                effect=Action.BLOCK,
                tools=frozenset({"inventory_db"}),
                operations=frozenset({"export"}),
                allow_external_destination=True,
            ),
            PolicyRule(
                rule_id="warehouse-review-write",
                effect=Action.REVIEW,
                tools=frozenset({"inventory_db"}),
                operations=frozenset({"update"}),
                maximum_impact=Impact.MULTIPLE_RECORDS,
            ),
            PolicyRule(
                rule_id="warehouse-read-stock",
                effect=Action.ALLOW,
                tools=frozenset({"inventory_db"}),
                operations=frozenset({"read"}),
                resources=frozenset({"stock_levels"}),
                maximum_data_classification=DataClassification.INTERNAL,
                maximum_impact=Impact.NONE,
            ),
        )
    )
    return ActionFirewall(PolicyEngine(policy))


def production_context() -> ActionContext:
    return ActionContext("inventory-agent", "operator-123", Environment.PRODUCTION)


def test_allows_explicitly_permitted_read() -> None:
    action = ToolAction("inventory_db", "read", "stock_levels")

    decision = warehouse_firewall().authorize(action, production_context())

    assert decision.action is Action.ALLOW
    assert decision.execution_allowed
    assert decision.policy_rule_id == "warehouse-read-stock"
    assert decision.blast_radius.score == 0


def test_requires_human_approval_for_inventory_update() -> None:
    action = ToolAction(
        "inventory_db",
        "update",
        "stock_levels",
        impact=Impact.MULTIPLE_RECORDS,
    )

    decision = warehouse_firewall().authorize(action, production_context())

    assert decision.action is Action.REVIEW
    assert decision.approval_required
    assert not decision.execution_allowed
    assert decision.blast_radius.score == 50


def test_blocks_external_customer_export() -> None:
    action = ToolAction(
        "inventory_db",
        "export",
        "customer_records",
        data_classification=DataClassification.RESTRICTED,
        impact=Impact.MULTIPLE_RECORDS,
        external_destination=True,
    )

    decision = warehouse_firewall().authorize(action, production_context())

    assert decision.action is Action.BLOCK
    assert decision.policy_rule_id == "warehouse-block-export"
    assert decision.blast_radius.level == "critical"


def test_blocks_unknown_tool_by_default() -> None:
    action = ToolAction("email", "send", "merchant")

    decision = warehouse_firewall().authorize(action, production_context())

    assert decision.action is Action.BLOCK
    assert decision.policy_rule_id is None
    assert "default action" in decision.reason


def test_critical_blast_radius_overrides_allow_with_review() -> None:
    permissive = PolicySet(
        rules=(PolicyRule("allow-delete", Action.ALLOW, operations=frozenset({"delete"})),)
    )
    action = ToolAction(
        "inventory_db",
        "delete",
        "all_shipments",
        impact=Impact.SYSTEM_WIDE,
    )

    decision = ActionFirewall(PolicyEngine(permissive)).authorize(action, production_context())

    assert decision.action is Action.REVIEW
    assert decision.blast_radius.score == 100
    assert "critical blast radius" in decision.reason
