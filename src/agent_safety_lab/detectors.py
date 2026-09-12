"""Deterministic baseline detectors.

These rules intentionally favor precision and explainability over broad claims
of protection. Later detectors can implement the same interface.
"""

import re
from dataclasses import dataclass

from agent_safety_lab.models import Finding


@dataclass(frozen=True, slots=True)
class PatternRule:
    rule_id: str
    category: str
    severity: int
    description: str
    pattern: re.Pattern[str]


RULES = (
    PatternRule(
        "ASL-PI-001",
        "instruction_override",
        80,
        "Attempts to override earlier instructions.",
        re.compile(
            r"\b(ignore|disregard|forget)\b.{0,40}"
            r"\b(previous|prior|above)\b.{0,20}"
            r"\b(instructions?|rules?|prompt)\b",
            re.IGNORECASE,
        ),
    ),
    PatternRule(
        "ASL-SE-001",
        "secret_extraction",
        90,
        "Requests disclosure of protected instructions or secrets.",
        re.compile(
            r"\b(reveal|show|print|expose|return)\b.{0,40}"
            r"\b(system prompt|api key|secret|credential|password)\b",
            re.IGNORECASE,
        ),
    ),
    PatternRule(
        "ASL-EX-001",
        "data_exfiltration",
        95,
        "Requests sensitive data to be sent to an external destination.",
        re.compile(
            r"\b(send|upload|post|forward|exfiltrate|export)\b.{0,80}"
            r"\b(customer|user|private|sensitive|database|credentials?)\b.{0,80}"
            r"\b(url|website|server|endpoint|email)\b",
            re.IGNORECASE,
        ),
    ),
    PatternRule(
        "ASL-DA-001",
        "destructive_action",
        100,
        "Requests a potentially destructive system or data action.",
        re.compile(
            r"\b(drop\s+table|delete\s+all|rm\s+-rf|wipe\s+(the\s+)?database|"
            r"destroy\s+(the\s+)?data)\b",
            re.IGNORECASE,
        ),
    ),
)


class PromptInjectionDetector:
    """Scan text against stable, human-readable baseline rules."""

    def detect(self, text: str) -> tuple[Finding, ...]:
        if not isinstance(text, str):
            raise TypeError("text must be a string")

        return tuple(
            Finding(rule.rule_id, rule.category, rule.severity, rule.description)
            for rule in RULES
            if rule.pattern.search(text)
        )
