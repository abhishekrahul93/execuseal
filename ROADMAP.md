# Roadmap

## v0.1 — trustworthy foundation

- [x] Typed decision model and deterministic baseline detector
- [x] Initial threat model and architecture decision
- [x] Automated tests and Apache-2.0 licensing
- [x] Default-deny action policy engine
- [x] Blast-radius assessment and human-approval decisions
- [x] Privacy-aware, hash-chained audit evidence
- [ ] Structured attack fixtures and baseline metrics
- [ ] FastAPI gateway and OpenAPI contract
- [ ] CLI with machine-readable output and CI exit codes

## v0.2 — agent action security

- external YAML/JSON policy loading and schema validation
- resource patterns, principal scopes, quotas, and time constraints
- secrets and PII detectors with redaction
- signed audit checkpoints and durable storage adapter
- approval workflow with expiry and separation of duties
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
