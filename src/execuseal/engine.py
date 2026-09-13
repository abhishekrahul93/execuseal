"""Safety decision orchestration."""

from execuseal.detectors import PromptInjectionDetector, SensitiveDataDetector
from execuseal.models import Action, SafetyDecision


class SafetyEngine:
    """Evaluate input and map detector evidence to an enforcement action."""

    def __init__(
        self,
        detector: PromptInjectionDetector | None = None,
        sensitive_data_detector: SensitiveDataDetector | None = None,
    ) -> None:
        self._detector = detector or PromptInjectionDetector()
        self._sensitive_data_detector = sensitive_data_detector or SensitiveDataDetector()

    def evaluate(self, text: str) -> SafetyDecision:
        sensitive = self._sensitive_data_detector.detect(text)
        findings = self._detector.detect(text) + sensitive.findings
        risk_score = max((finding.severity for finding in findings), default=0)

        if risk_score >= 80:
            action = Action.BLOCK
        elif risk_score >= 50:
            action = Action.REVIEW
        else:
            action = Action.ALLOW

        return SafetyDecision(action, risk_score, findings, sensitive.redacted_text)
