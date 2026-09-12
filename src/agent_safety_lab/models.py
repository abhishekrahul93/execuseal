"""Domain models shared across detection and policy layers."""

from dataclasses import dataclass
from enum import StrEnum


class Action(StrEnum):
    """Enforcement recommendation produced by the safety engine."""

    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class Finding:
    """An explainable signal emitted by a detector."""

    rule_id: str
    category: str
    severity: int
    description: str


@dataclass(frozen=True, slots=True)
class SafetyDecision:
    """Aggregate assessment returned to an enforcement point."""

    action: Action
    risk_score: int
    findings: tuple[Finding, ...]

    @property
    def safe(self) -> bool:
        """Return true only when the policy explicitly allows the request."""

        return self.action is Action.ALLOW
