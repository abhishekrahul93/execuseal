"""Deterministic, default-deny authorization policy for agent tool actions."""

from dataclasses import dataclass

from execuseal.actions import (
    ActionContext,
    DataClassification,
    Environment,
    Impact,
    ToolAction,
)
from execuseal.models import Action


@dataclass(frozen=True, slots=True)
class PolicyRule:
    rule_id: str
    effect: Action
    tools: frozenset[str] = frozenset({"*"})
    operations: frozenset[str] = frozenset({"*"})
    resources: frozenset[str] = frozenset({"*"})
    environments: frozenset[Environment] = frozenset(Environment)
    maximum_data_classification: DataClassification = DataClassification.RESTRICTED
    maximum_impact: Impact = Impact.SYSTEM_WIDE
    allow_external_destination: bool = False

    def matches(self, action: ToolAction, context: ActionContext) -> bool:
        return (
            _matches(self.tools, action.tool)
            and _matches(self.operations, action.operation)
            and _matches(self.resources, action.resource)
            and context.environment in self.environments
            and action.data_classification <= self.maximum_data_classification
            and action.impact <= self.maximum_impact
            and (not action.external_destination or self.allow_external_destination)
        )


@dataclass(frozen=True, slots=True)
class PolicySet:
    rules: tuple[PolicyRule, ...]
    default_action: Action = Action.BLOCK

    def __post_init__(self) -> None:
        identifiers = [rule.rule_id for rule in self.rules]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("policy rule IDs must be unique")


@dataclass(frozen=True, slots=True)
class PolicyResult:
    action: Action
    matched_rule_id: str | None
    reason: str


class PolicyEngine:
    """Evaluate rules in declared order; first match wins."""

    def __init__(self, policy: PolicySet) -> None:
        self._policy = policy

    def evaluate(self, action: ToolAction, context: ActionContext) -> PolicyResult:
        for rule in self._policy.rules:
            if rule.matches(action, context):
                return PolicyResult(
                    rule.effect,
                    rule.rule_id,
                    f"Matched policy rule {rule.rule_id}.",
                )

        return PolicyResult(
            self._policy.default_action,
            None,
            "No policy rule matched; applied the default action.",
        )


def _matches(allowed: frozenset[str], value: str) -> bool:
    return "*" in allowed or value in allowed
