# Security Policy

This project is pre-alpha and must not be treated as a complete security
boundary. Do not deploy it as the only control protecting high-impact systems.

Please do not open public issues for suspected vulnerabilities. Until a private
reporting address is established, use GitHub's private vulnerability reporting
feature on the repository. Include reproduction steps, expected impact, and the
affected version. We will acknowledge reports when the public repository is
launched and publish a supported-version policy before the first stable release.

## Deployment warning

The current API-key mechanism is an initial authenticated boundary. Use HTTPS,
store keys outside source control, restrict network exposure, and rotate any key
that may have leaked. Reviewer keys must be held by humans or approval services,
kept separate from agent keys, and rotated independently. PostgreSQL persistence is
available, but external signed
checkpoints are still required to detect deletion or replacement of the entire
database.

Service API keys are stored only as SHA-256 digests and checked for scope,
expiry, and revocation on every request. Keep bootstrap admin keys offline where
possible, issue narrow short-lived identities, and rotate by issuing a new key
before revoking the old one. Generated raw keys cannot be recovered.

Use a dedicated checkpoint signing key, store it outside the gateway, and copy
checkpoint JSON to independent append-only or object-lock storage. A checkpoint
left in the same database or writable host cannot detect whole-system rollback.

Authorization signing keys are Ed25519 private keys. Never expose the private
key-ring environment variable to agents or tool executors. Executors should
consume only the published public keys over an authenticated TLS channel.
During rotation, keep old public keys available until their final token has
expired. Replay protection depends on every verifier sharing the same durable
database.

The included container runs as a non-root user with a read-only filesystem and
dropped capabilities. The Compose port binds to localhost; do not expose it
publicly without TLS, network policy, monitoring, secret management, backups,
and an incident-response plan.

## Operational telemetry

Protect `/metrics` with a dedicated `EXECUSEAL_METRICS_API_KEYS` credential and
restrict it at the network layer to the monitoring system. Metrics intentionally
exclude prompts, parameters, identity values, and resource names. Treat request
logs and aggregate safety decisions as security-sensitive operational data;
apply access controls and a documented retention period.

The scanner can return a redacted copy for selected sensitive-value formats,
but the original request still existed in the calling process and HTTP path.
Callers must avoid logging request bodies and must explicitly pass the redacted
copy downstream. Detection is high-confidence and incomplete; it is not a
general-purpose data-loss-prevention guarantee.
