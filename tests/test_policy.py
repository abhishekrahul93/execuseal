import pytest

from execuseal import (
    Action,
    ActionContext,
    DataClassification,
    Environment,
    Impact,
    PolicyEngine,
    PolicyRule,
    PolicySet,
    ToolAction,
)


def test_policy_rejects_duplicate_rule_ids() -> None:
    duplicate = PolicyRule("same-id", Action.ALLOW)

    with pytest.raises(ValueError, match="unique"):
        PolicySet((duplicate, duplicate))


def test_action_metadata_is_immutable() -> None:
    parameters = {"limit": 10}
    action = ToolAction("db", "read", "orders", parameters=parameters)
    parameters["limit"] = 999

    assert action.parameters["limit"] == 10
    with pytest.raises(TypeError):
        action.parameters["limit"] = 20  # type: ignore[index]


@pytest.mark.parametrize(
    "factory",
    [
        lambda: ToolAction("", "read", "orders"),
        lambda: ActionContext("", "person", Environment.DEVELOPMENT),
    ],
)
def test_identifiers_must_not_be_empty(factory: object) -> None:
    with pytest.raises(ValueError):
        factory()  # type: ignore[operator]


def test_rule_enforces_classification_and_environment() -> None:
    policy = PolicySet(
        (
            PolicyRule(
                "dev-read",
                Action.ALLOW,
                tools=frozenset({"db"}),
                operations=frozenset({"read"}),
                environments=frozenset({Environment.DEVELOPMENT}),
                maximum_data_classification=DataClassification.INTERNAL,
                maximum_impact=Impact.NONE,
            ),
        )
    )
    action = ToolAction(
        "db",
        "read",
        "payments",
        data_classification=DataClassification.CONFIDENTIAL,
    )
    context = ActionContext("agent", "person", Environment.DEVELOPMENT)

    result = PolicyEngine(policy).evaluate(action, context)

    assert result.action is Action.BLOCK
    assert result.matched_rule_id is None
