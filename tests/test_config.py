import json
from pathlib import Path

import pytest

from agent_safety_lab import Action, PolicyConfigError, load_policy, parse_policy


def valid_policy() -> dict[str, object]:
    return {
        "version": 1,
        "default_action": "block",
        "rules": [
            {
                "id": "allow-read",
                "effect": "allow",
                "tools": ["db"],
                "operations": ["read"],
            }
        ],
    }


@pytest.mark.parametrize("suffix", [".yml", ".json"])
def test_loads_yaml_and_json_policies(tmp_path: Path, suffix: str) -> None:
    path = tmp_path / f"policy{suffix}"
    path.write_text(json.dumps(valid_policy()), encoding="utf-8")

    policy = load_policy(path)

    assert policy.default_action is Action.BLOCK
    assert policy.rules[0].rule_id == "allow-read"


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"version": 2}, "version"),
        ({"unexpected": True}, "unknown fields"),
        ({"rules": []}, "non-empty list"),
    ],
)
def test_rejects_invalid_policy(change: dict[str, object], message: str) -> None:
    raw = valid_policy()
    raw.update(change)

    with pytest.raises(PolicyConfigError, match=message):
        parse_policy(raw)


def test_rejects_unknown_rule_field() -> None:
    raw = valid_policy()
    rules = raw["rules"]
    assert isinstance(rules, list)
    rules[0]["surprise"] = True

    with pytest.raises(PolicyConfigError, match="unknown fields"):
        parse_policy(raw)


def test_wraps_missing_file_error(tmp_path: Path) -> None:
    with pytest.raises(PolicyConfigError, match="Cannot read"):
        load_policy(tmp_path / "missing.yml")
