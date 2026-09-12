# Architecture

## Decision ADR-001: modular monolith first

Start as one Python package with clean internal boundaries. This keeps testing,
installation, and contribution simple while preserving future service splits.

```text
Untrusted input -> Detectors -> Risk aggregation -> Policy -> Decision
                                                        |
                                                        v
                                                Audit / enforcement
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

## Planned boundaries

- `core`: contracts, decisions, scoring
- `detectors`: prompt, secret, PII, exfiltration, and tool-risk signals
- `policies`: configurable deterministic enforcement
- `gateway`: FastAPI request and tool-call interception
- `benchmarks`: versioned adversarial cases and metrics
- `cli`: local scans and CI/CD safety gates
- `audit`: privacy-aware event records
