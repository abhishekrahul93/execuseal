import pytest

from execuseal import Action, SafetyEngine, SensitiveDataDetector


@pytest.mark.parametrize(
    ("text", "rule_id", "replacement"),
    [
        ("Contact rahul@example.com", "ASL-PII-001", "[REDACTED_EMAIL]"),
        ("Call +49 151 23456789", "ASL-PII-002", "[REDACTED_PHONE]"),
        ("IBAN DE89 3704 0044 0532 0130 00", "ASL-PII-003", "[REDACTED_IBAN]"),
        ("SSN 123-45-6789", "ASL-PII-004", "[REDACTED_SSN]"),
        ("Card 4111 1111 1111 1111", "ASL-PII-005", "[REDACTED_PAYMENT_CARD]"),
        (
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234",
            "ASL-SC-003",
            "Bearer [REDACTED_TOKEN]",
        ),
        (
            "api_key=abcdefghijklmnopqrstuvwxyz123456",
            "ASL-SC-004",
            "[REDACTED_SECRET]",
        ),
    ],
)
def test_detects_and_redacts_without_returning_raw_value(
    text: str,
    rule_id: str,
    replacement: str,
) -> None:
    result = SensitiveDataDetector().detect(text)

    assert {finding.rule_id for finding in result.findings} == {rule_id}
    assert result.redacted_text is not None
    assert replacement in result.redacted_text
    assert text.split()[-1] not in result.redacted_text


def test_redacts_complete_private_key_block() -> None:
    private_key = "-----BEGIN PRIVATE KEY-----\nvery-secret-material\n-----END PRIVATE KEY-----"
    result = SensitiveDataDetector().detect(f"Use this:\n{private_key}\nthanks")

    assert result.findings[0].rule_id == "ASL-SC-001"
    assert result.redacted_text == "Use this:\n[REDACTED_PRIVATE_KEY]\nthanks"
    assert "very-secret-material" not in result.redacted_text


def test_rejects_invalid_payment_card_and_common_lookalikes() -> None:
    text = "Order 4111 1111 1111 1112 and version 123-45-0000 are test references."

    assert SensitiveDataDetector().detect(text).findings == ()
    assert SensitiveDataDetector().detect(text).redacted_text is None


def test_sensitive_data_changes_enforcement_without_echoing_safe_input() -> None:
    pii = SafetyEngine().evaluate("Email me at rahul@example.com")
    secret = SafetyEngine().evaluate("api_key=abcdefghijklmnopqrstuvwxyz123456")
    benign = SafetyEngine().evaluate("Summarize the warehouse report")

    assert pii.action is Action.REVIEW
    assert pii.redacted_text == "Email me at [REDACTED_EMAIL]"
    assert secret.action is Action.BLOCK
    assert secret.redacted_text == "[REDACTED_SECRET]"
    assert benign.action is Action.ALLOW
    assert benign.redacted_text is None
