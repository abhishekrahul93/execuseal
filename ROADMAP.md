# Roadmap

## v0.1 — trustworthy foundation

- [x] Typed decision model and deterministic baseline detector
- [x] Initial threat model and architecture decision
- [x] Automated tests and Apache-2.0 licensing
- [x] Default-deny action policy engine
- [x] Blast-radius assessment and human-approval decisions
- [x] Privacy-aware, hash-chained audit evidence
- [x] Validated YAML/JSON policy-as-code
- [x] Structured attack fixtures and baseline metrics
- [x] CLI with machine-readable output and CI exit codes
- [x] Authenticated FastAPI gateway and OpenAPI contract
- [x] Prompt and tool-action interception endpoints
- [x] PostgreSQL-backed hash-chain audit persistence
- [x] Single-instance rate limiting and structured request logs
- [x] Hardened Docker image and PostgreSQL Compose stack
- [x] MCP `tools/call` interception baseline
- [x] Action-bound signed decisions with expiry and replay protection
- [x] Unsafe warehouse-agent execution proof
- [x] Persistent approval workflow with expiry and separation of duties

## v0.2 — agent action security

- resource patterns, principal scopes, quotas, and time constraints
- secrets and PII detectors with redaction
- signed audit checkpoints and durable storage adapter
- scoped service identities and API-key rotation/revocation
- schema migrations and signed external integrity checkpoints
- distributed rate limiting
- indirect prompt-injection benchmark

## v0.3 — integrations and evaluation

- OpenAI-compatible and MCP adapters
- semantic detector as an optional defense layer
- false-positive, attack-success, latency, and cost reporting
- GitHub Action and reference applications

## Production milestone

Authentication, rate limiting, PostgreSQL, observability, documented data
retention, deployment hardening, third-party security review, stable SDK/CLI,
and measured benchmark results. No version will promise complete safety.
