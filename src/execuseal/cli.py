"""Command-line safety checks for local development and CI/CD."""

import argparse
import base64
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from execuseal.audit_store import SqlAuditStore
from execuseal.benchmark import BenchmarkFormatError, BenchmarkRunner
from execuseal.checkpoints import AuditCheckpoint, create_checkpoint, verify_checkpoint
from execuseal.config import PolicyConfigError, load_policy
from execuseal.engine import SafetyEngine
from execuseal.migrations import upgrade
from execuseal.tokens import public_keys_from_base64


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="execuseal")
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
    database = subcommands.add_parser("db", help="Database schema operations")
    database_commands = database.add_subparsers(dest="database_command", required=True)
    upgrade_parser = database_commands.add_parser("upgrade", help="Apply schema migrations")
    upgrade_parser.add_argument("--database-url", required=True)
    audit = subcommands.add_parser("audit", help="Audit integrity operations")
    audit_commands = audit.add_subparsers(dest="audit_command", required=True)
    checkpoint = audit_commands.add_parser("checkpoint", help="Create or verify checkpoints")
    checkpoint_commands = checkpoint.add_subparsers(dest="checkpoint_command", required=True)
    create = checkpoint_commands.add_parser("create", help="Create a signed checkpoint")
    create.add_argument("--database-url", required=True)
    create.add_argument("--key-id", required=True)
    create.add_argument("--private-key-file", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    verify = checkpoint_commands.add_parser("verify", help="Verify DB against checkpoint")
    verify.add_argument("--database-url", required=True)
    verify.add_argument("--public-keys-file", type=Path, required=True)
    verify.add_argument("--checkpoint", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "test":
            return _test(args)
        if args.command == "db":
            applied = upgrade(args.database_url)
            print("Applied: " + ", ".join(applied) if applied else "Database is current")
            return 0
        if args.command == "audit":
            return _checkpoint(args)
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


def _checkpoint(args: argparse.Namespace) -> int:
    store = SqlAuditStore(args.database_url)
    if args.checkpoint_command == "create":
        encoded = args.private_key_file.read_text(encoding="utf-8").strip()
        private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(encoded))
        checkpoint = create_checkpoint(store, private_key, args.key_id)
        args.output.write_text(checkpoint.to_json() + "\n", encoding="utf-8")
        print(f"Checkpoint written: {args.output}")
        return 0
    checkpoint = AuditCheckpoint.from_json(args.checkpoint.read_text(encoding="utf-8"))
    encoded_keys = json.loads(args.public_keys_file.read_text(encoding="utf-8"))
    verify_checkpoint(checkpoint, public_keys_from_base64(encoded_keys), store)
    print("Checkpoint valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
