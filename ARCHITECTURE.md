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

## Decision ADR-004: versioned strict configuration

Policies are JSON or YAML documents with an explicit schema version. Loading
uses safe YAML parsing, rejects unknown fields, validates enum values, and fails
before runtime enforcement begins. Versioning creates a migration path without
silently changing policy meaning.

## Decision ADR-005: reproducible safety gates

Benchmarks use reviewable JSON Lines fixtures and calculate precision, recall,
F1, false-positive rate, and mean detector latency at runtime. CI gates on F1
because accuracy can hide failures in an imbalanced dataset. Benchmark results
must always name the dataset version and may not be generalized beyond it.

## Decision ADR-006: decision point, not execution proxy

The FastAPI gateway receives action metadata and returns an authorization
decision before execution. It does not receive downstream tool credentials and
does not execute the proposed action. Host applications remain responsible for
enforcing `execution_allowed=false`; future signed decision tokens will reduce
the risk of a compromised host ignoring the result.

The initial API uses API-key authentication, strict request schemas, bounded
input sizes, request correlation, and no-store response headers. API keys are a
bootstrap mechanism, not the final identity model. The process-local audit chain
is explicitly non-production until a durable, concurrency-safe adapter exists.

## Decision ADR-007: durable hash-chain serialization

Audit records are persisted through SQLAlchemy. PostgreSQL transactions acquire
an advisory lock before reading the chain head and inserting the next record,
so concurrent gateway workers cannot create two successors for one hash. SQLite
is a development option; production configuration refuses it.

## Decision ADR-008: bounded single-instance traffic

Authenticated requests use a thread-safe, per-key fixed-window limiter. Keys
are represented internally by SHA-256 fingerprints and never logged. A shared
rate-limit backend remains required for distributed deployment.

## Decision ADR-009: asymmetric, action-bound authorization

An allowed action may receive a compact Ed25519 token containing a digest
of verified identity, environment, tool, resource, classification, impact and
arguments. Tokens expire within a bounded interval and are single-use. This
prevents changing arguments between authorization and execution and blocks
replay across processes through an atomic SQL token-ID insert. Tokens carry an
issuer, audience, version, and key ID. The gateway signs with the active private
key; separate executors verify with public keys only. Rotation retains old
public keys through the maximum token lifetime without distributing old private
keys.

## Decision ADR-010: MCP metadata is untrusted

The MCP adapter handles JSON-RPC `tools/call` requests. Security attributes come
from locally trusted tool profiles, never tool descriptions, annotations or
model-supplied arguments. Denied and review-required calls return tool execution
errors and never invoke the downstream handler.

## Decision ADR-011: approvals require separation of duties

Review decisions use credentials distinct from agent gateway credentials. A
pending request stores only identity and resource metadata plus a canonical
digest of the complete action. The reviewer must resubmit the exact action;
changed arguments fail digest verification. SQL performs a conditional state
transition from `pending` to `approved` or `rejected`, making the decision
single-use under concurrent requests. Requests expire, and only an approved
request receives a short-lived execution token.

## Decision ADR-012: scoped, revocable service identities

API keys are represented by SHA-256 digests in SQL and map to a principal,
explicit scopes, optional expiry, and revocation state. Raw generated keys are
returned once. Authentication checks scope and lifecycle state on every request,
so revocation applies immediately across workers. Bootstrap agent and admin keys
are separated and receive different fixed scopes.

## Decision ADR-013: versioned, fail-closed schema changes

Ordered migrations are recorded in `schema_migrations`. Development can apply
missing migrations automatically; production startup only verifies the expected
version and refuses service when the schema is absent or stale. Deployment runs
`execuseal db upgrade` before starting the gateway.
