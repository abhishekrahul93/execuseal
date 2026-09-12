"""Pre-execution enforcement for AI-agent tool actions."""

from dataclasses import dataclass

from agent_safety_lab.actions import ActionContext, ToolAction
from agent_safety_lab.blast_radius import BlastRadius, BlastRadiusAssessor
from agent_safety_lab.models import Action
from agent_safety_lab.policy import PolicyEngine


@dataclass(frozen=True, slots=True)
class ActionDecision:
    action: Action
    policy_rule_id: str | None
    blast_radius: BlastRadius
    reason: str

    @property
    def execution_allowed(self) -> bool:
        return self.action is Action.ALLOW

    @property
    def approval_required(self) -> bool:
        return self.action is Action.REVIEW


class ActionFirewall:
    """Combine explicit authorization policy with impact assessment."""

    def __init__(
        self,
        policy_engine: PolicyEngine,
        assessor: BlastRadiusAssessor | None = None,
    ) -> None:
        self._policy_engine = policy_engine
        self._assessor = assessor or BlastRadiusAssessor()

    def authorize(self, action: ToolAction, context: ActionContext) -> ActionDecision:
        policy_result = self._policy_engine.evaluate(action, context)
        blast_radius = self._assessor.assess(action, context.environment)
        outcome = policy_result.action
        reason = policy_result.reason

        if outcome is Action.ALLOW and blast_radius.score >= 80:
            outcome = Action.REVIEW
            reason = "Policy allowed the action, but critical blast radius requires approval."

        return ActionDecision(
            action=outcome,
            policy_rule_id=policy_result.matched_rule_id,
            blast_radius=blast_radius,
            reason=reason,
        )
