# Architecture

## Decision ADR-001: modular monolith first

Start as one Python package with clean internal boundaries. This keeps testing,
installation, and contribution simple while preserving future service splits.

```text
Untrusted content -> Detectors -----------+
                                            v
Proposed tool action -> Blast radius -> Policy -> Decision -> Host enforcement
                                            |          |
Verified identity/environment -------------+          v
                                                  Audit evidence
```

The core must not depend on a specific LLM provider. Network-dependent and
probabilistic detectors will be optional adapters; deterministic policy remains
the final enforcement layer.

## Core contracts

- A detector emits zero or more immutable findings.
- A finding has a stable rule ID, category, severity, and explanation.
- The engine aggregates findings into a bounded risk score.
- Policy converts evidence into `allow`, `review`, or `block`.
- Enforcement occurs outside the model and before the proposed action.
- No tool parameters, prompts, credentials, or record values enter audit events.

## Decision ADR-002: default-deny action policy

Tool actions require a matching rule. An unknown tool, operation, resource, or
environment is blocked. Rules use first-match semantics, making precedence
visible and deterministic. A critical blast-radius assessment downgrades an
`allow` decision to `review`, but never upgrades a block.

## Decision ADR-003: tamper-evident, data-minimized auditing

Audit events contain identifiers and decision metadata, not raw content. Each
record includes the previous record hash. This detects in-chain modification,
but production integrity additionally requires signed checkpoints and external
durable storage to detect truncation or total replacement.

## Planned boundaries

- `core`: contracts, decisions, scoring
- `detectors`: prompt, secret, PII, exfiltration, and tool-risk signals
- `policies`: configurable deterministic enforcement
- `gateway`: FastAPI request and tool-call interception
- `benchmarks`: versioned adversarial cases and metrics
- `cli`: local scans and CI/CD safety gates
- `audit`: privacy-aware event records
