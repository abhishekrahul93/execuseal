"""Deterministic baseline detectors.

These rules intentionally favor precision and explainability over broad claims
of protection. Later detectors can implement the same interface.
"""

import re
from dataclasses import dataclass

from execuseal.models import Finding


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


@dataclass(frozen=True, slots=True)
class SensitiveRule:
    rule_id: str
    category: str
    severity: int
    description: str
    replacement: str
    pattern: re.Pattern[str]


SENSITIVE_RULES = (
    SensitiveRule(
        "ASL-SC-001",
        "private_key",
        100,
        "Contains private-key material.",
        "[REDACTED_PRIVATE_KEY]",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
            r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    SensitiveRule(
        "ASL-SC-002",
        "cloud_credential",
        95,
        "Contains a credential-shaped access key.",
        "[REDACTED_CREDENTIAL]",
        re.compile(
            r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,255}|"
            r"sk-[A-Za-z0-9_-]{20,})\b"
        ),
    ),
    SensitiveRule(
        "ASL-SC-003",
        "authentication_token",
        95,
        "Contains a bearer authentication token.",
        "Bearer [REDACTED_TOKEN]",
        re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}", re.IGNORECASE),
    ),
    SensitiveRule(
        "ASL-SC-004",
        "assigned_secret",
        90,
        "Contains a secret assigned to a credential field.",
        "[REDACTED_SECRET]",
        re.compile(
            r"\b(?:api[_-]?key|client[_-]?secret|password|access[_-]?token)"
            r"\s*[:=]\s*[\"']?[A-Za-z0-9._~+/=-]{16,}[\"']?",
            re.IGNORECASE,
        ),
    ),
    SensitiveRule(
        "ASL-PII-001",
        "email_address",
        55,
        "Contains an email address.",
        "[REDACTED_EMAIL]",
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", re.IGNORECASE),
    ),
    SensitiveRule(
        "ASL-PII-002",
        "international_phone_number",
        55,
        "Contains an international phone number.",
        "[REDACTED_PHONE]",
        re.compile(r"(?<!\w)\+(?:\d[ .()-]?){7,14}\d(?!\w)"),
    ),
    SensitiveRule(
        "ASL-PII-003",
        "iban",
        70,
        "Contains an IBAN-shaped financial identifier.",
        "[REDACTED_IBAN]",
        re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b"),
    ),
    SensitiveRule(
        "ASL-PII-004",
        "us_social_security_number",
        85,
        "Contains a US Social Security number.",
        "[REDACTED_SSN]",
        re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)"),
    ),
)
CREDIT_CARD_PATTERN = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")


@dataclass(frozen=True, slots=True)
class SensitiveDataResult:
    findings: tuple[Finding, ...]
    redacted_text: str | None


class SensitiveDataDetector:
    """Detect and redact high-confidence secrets and common PII formats."""

    def detect(self, text: str) -> SensitiveDataResult:
        if not isinstance(text, str):
            raise TypeError("text must be a string")

        redacted = text
        findings: list[Finding] = []
        for rule in SENSITIVE_RULES:
            redacted, replacements = rule.pattern.subn(rule.replacement, redacted)
            if replacements:
                findings.append(
                    Finding(rule.rule_id, rule.category, rule.severity, rule.description)
                )
        card_matches = [
            match
            for match in CREDIT_CARD_PATTERN.finditer(redacted)
            if _valid_luhn(match.group())
        ]
        for match in reversed(card_matches):
            redacted = (
                redacted[: match.start()] + "[REDACTED_PAYMENT_CARD]" + redacted[match.end() :]
            )
        if card_matches:
            findings.append(
                Finding(
                    "ASL-PII-005",
                    "payment_card_number",
                    85,
                    "Contains a checksum-valid payment card number.",
                )
            )
        return SensitiveDataResult(tuple(findings), redacted if findings else None)


def _valid_luhn(value: str) -> bool:
    digits = [int(character) for character in value if character.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0
