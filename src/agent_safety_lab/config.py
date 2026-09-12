"""Strict loading of versioned policy-as-code documents."""

import json
from pathlib import Path
from typing import Any

import yaml

from agent_safety_lab.actions import DataClassification, Environment, Impact
from agent_safety_lab.models import Action
from agent_safety_lab.policy import PolicyRule, PolicySet

POLICY_KEYS = frozenset({"version", "default_action", "rules"})
RULE_KEYS = frozenset(
    {
        "id",
        "effect",
        "tools",
        "operations",
        "resources",
        "environments",
        "maximum_data_classification",
        "maximum_impact",
        "allow_external_destination",
    }
)


class PolicyConfigError(ValueError):
    """Raised when a policy document is invalid or unsupported."""


def load_policy(path: str | Path) -> PolicySet:
    """Load and validate a JSON or YAML policy without unsafe YAML constructors."""

    policy_path = Path(path)
    try:
        text = policy_path.read_text(encoding="utf-8")
    except OSError as error:
        raise PolicyConfigError(f"Cannot read policy: {error}") from error

    try:
        raw = json.loads(text) if policy_path.suffix.lower() == ".json" else yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as error:
        raise PolicyConfigError(f"Cannot parse policy: {error}") from error

    return parse_policy(raw)


def parse_policy(raw: object) -> PolicySet:
    document = _mapping(raw, "policy")
    _reject_unknown(document, POLICY_KEYS, "policy")
    if document.get("version") != 1:
        raise PolicyConfigError("policy.version must equal 1")

    default_action = _enum(Action, document.get("default_action", "block"), "default_action")
    rules_raw = document.get("rules")
    if not isinstance(rules_raw, list) or not rules_raw:
        raise PolicyConfigError("policy.rules must be a non-empty list")

    rules = tuple(_parse_rule(item, index) for index, item in enumerate(rules_raw))
    return PolicySet(rules=rules, default_action=default_action)


def _parse_rule(raw: object, index: int) -> PolicyRule:
    label = f"rules[{index}]"
    rule = _mapping(raw, label)
    _reject_unknown(rule, RULE_KEYS, label)
    rule_id = rule.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise PolicyConfigError(f"{label}.id must be a non-empty string")

    allow_external = rule.get("allow_external_destination", False)
    if not isinstance(allow_external, bool):
        raise PolicyConfigError(f"{label}.allow_external_destination must be boolean")

    return PolicyRule(
        rule_id=rule_id,
        effect=_enum(Action, rule.get("effect"), f"{label}.effect"),
        tools=_strings(rule.get("tools", ["*"]), f"{label}.tools"),
        operations=_strings(rule.get("operations", ["*"]), f"{label}.operations"),
        resources=_strings(rule.get("resources", ["*"]), f"{label}.resources"),
        environments=frozenset(
            _enum(Environment, item, f"{label}.environments")
            for item in _list(rule.get("environments", [item.value for item in Environment]), label)
        ),
        maximum_data_classification=_enum(
            DataClassification,
            rule.get("maximum_data_classification", "restricted"),
            f"{label}.maximum_data_classification",
        ),
        maximum_impact=_enum(
            Impact,
            rule.get("maximum_impact", "system_wide"),
            f"{label}.maximum_impact",
        ),
        allow_external_destination=allow_external,
    )


def _mapping(raw: object, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict) or not all(isinstance(key, str) for key in raw):
        raise PolicyConfigError(f"{label} must be an object")
    return raw


def _list(raw: object, label: str) -> list[object]:
    if not isinstance(raw, list) or not raw:
        raise PolicyConfigError(f"{label} must be a non-empty list")
    return raw


def _strings(raw: object, label: str) -> frozenset[str]:
    values = _list(raw, label)
    if not all(isinstance(value, str) and value.strip() for value in values):
        raise PolicyConfigError(f"{label} values must be non-empty strings")
    return frozenset(str(value) for value in values)


def _enum(enum_type: type[Any], raw: object, label: str) -> Any:
    try:
        if isinstance(raw, str):
            return enum_type[raw.upper()]
        return enum_type(raw)
    except (KeyError, TypeError, ValueError) as error:
        allowed = ", ".join(str(item.name).lower() for item in enum_type)
        raise PolicyConfigError(f"{label} must be one of: {allowed}") from error


def _reject_unknown(document: dict[str, Any], allowed: frozenset[str], label: str) -> None:
    unknown = sorted(set(document) - allowed)
    if unknown:
        raise PolicyConfigError(f"{label} contains unknown fields: {', '.join(unknown)}")
