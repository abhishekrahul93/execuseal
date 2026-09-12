"""Explainable estimation of the damage a proposed action could cause."""

from dataclasses import dataclass

from agent_safety_lab.actions import DataClassification, Environment, Impact, ToolAction


@dataclass(frozen=True, slots=True)
class BlastRadius:
    score: int
    level: str
    reasons: tuple[str, ...]


class BlastRadiusAssessor:
    """Calculate a bounded risk score without executing the action."""

    def assess(self, action: ToolAction, environment: Environment) -> BlastRadius:
        score = int(action.impact) * 20
        reasons: list[str] = []

        if action.impact >= Impact.MULTIPLE_RECORDS:
            reasons.append("Action may affect multiple records or resources.")
        if action.data_classification >= DataClassification.CONFIDENTIAL:
            score += 20
            reasons.append("Action touches confidential or restricted data.")
        if action.external_destination:
            score += 30
            reasons.append("Action sends data beyond the protected boundary.")
        if action.operation.lower() in {"delete", "drop", "destroy", "execute"}:
            score += 30
            reasons.append("Action uses a destructive or arbitrary-execution operation.")
        if environment is Environment.PRODUCTION and action.impact > Impact.NONE:
            score += 10
            reasons.append("Action targets the production environment.")

        bounded_score = min(score, 100)
        if bounded_score >= 80:
            level = "critical"
        elif bounded_score >= 50:
            level = "high"
        elif bounded_score >= 20:
            level = "medium"
        else:
            level = "low"

        return BlastRadius(bounded_score, level, tuple(reasons))
