"""Command-line safety checks for local development and CI/CD."""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from agent_safety_lab.benchmark import BenchmarkFormatError, BenchmarkRunner
from agent_safety_lab.config import PolicyConfigError, load_policy
from agent_safety_lab.engine import SafetyEngine


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentsafety")
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser("scan", help="Scan one prompt for baseline threats")
    source = scan.add_mutually_exclusive_group(required=True)
    source.add_argument("--text", help="Text to scan")
    source.add_argument("--file", type=Path, help="UTF-8 text file to scan")
    scan.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    test = subcommands.add_parser("test", help="Run a versioned safety benchmark")
    test.add_argument("dataset", type=Path, help="JSONL benchmark dataset")
    test.add_argument("--minimum-score", type=float, default=80.0)
    test.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    policy = subcommands.add_parser("policy", help="Policy-as-code operations")
    policy_commands = policy.add_subparsers(dest="policy_command", required=True)
    validate = policy_commands.add_parser("validate", help="Validate a YAML/JSON policy")
    validate.add_argument("path", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "test":
            return _test(args)
        return _validate_policy(args)
    except (OSError, PolicyConfigError, BenchmarkFormatError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


def _scan(args: argparse.Namespace) -> int:
    text = args.text if args.text is not None else args.file.read_text(encoding="utf-8")
    decision = SafetyEngine().evaluate(text)
    payload = {
        "action": decision.action.value,
        "risk_score": decision.risk_score,
        "findings": [
            {
                "rule_id": finding.rule_id,
                "category": finding.category,
                "severity": finding.severity,
                "description": finding.description,
            }
            for finding in decision.findings
        ],
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(f"Action: {decision.action.value.upper()}  Risk: {decision.risk_score}/100")
        for finding in decision.findings:
            print(f"- {finding.rule_id}: {finding.description}")
    return 0 if decision.safe else 1


def _test(args: argparse.Namespace) -> int:
    result = BenchmarkRunner().run(args.dataset, args.minimum_score)
    if args.json:
        print(json.dumps(result.to_dict(), sort_keys=True))
    else:
        print(f"Cases: {result.total_cases}")
        print(f"Precision: {result.precision:.2%}")
        print(f"Recall: {result.recall:.2%}")
        print(f"F1 safety score: {result.f1_score * 100:.2f}/100")
        print(f"False-positive rate: {result.false_positive_rate:.2%}")
        print(f"Mean latency: {result.mean_latency_ms:.4f} ms")
        print("Result: PASS" if result.passed else "Result: FAIL")
    return 0 if result.passed else 1


def _validate_policy(args: argparse.Namespace) -> int:
    policy = load_policy(args.path)
    print(f"Valid policy v1: {len(policy.rules)} rule(s), default={policy.default_action.value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
