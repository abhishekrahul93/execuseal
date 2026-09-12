"""Safety decision orchestration."""

from agent_safety_lab.detectors import PromptInjectionDetector
from agent_safety_lab.models import Action, SafetyDecision


class SafetyEngine:
    """Evaluate input and map detector evidence to an enforcement action."""

    def __init__(self, detector: PromptInjectionDetector | None = None) -> None:
        self._detector = detector or PromptInjectionDetector()

    def evaluate(self, text: str) -> SafetyDecision:
        findings = self._detector.detect(text)
        risk_score = max((finding.severity for finding in findings), default=0)

        if risk_score >= 80:
            action = Action.BLOCK
        elif risk_score >= 50:
            action = Action.REVIEW
        else:
            action = Action.ALLOW

        return SafetyDecision(action, risk_score, findings)
