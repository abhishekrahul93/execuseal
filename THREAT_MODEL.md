# Threat Model v0.1

## System being protected

An AI agent that receives untrusted input and may call tools such as databases,
HTTP APIs, email, file systems, browsers, or MCP servers.

## Security objectives

- Prevent unauthorized or destructive tool actions.
- Reduce leakage of secrets, personal data, and protected instructions.
- Detect attempts to alter the agent's intended goal or authority.
- Preserve evidence sufficient to explain and audit decisions.
- Fail closed when a high-impact action cannot be evaluated safely.

## Trust boundaries

Untrusted: user prompts, retrieved documents, websites, tool output, agent
memory, third-party MCP metadata, and model-generated tool arguments.

Conditionally trusted: application policy, authenticated identity and scopes,
detector configuration, approval decisions, and audit storage.

## Initial threat categories

| ID | Threat | Commit #1 coverage |
|---|---|---|
| T1 | Direct instruction override | Baseline pattern detection |
| T2 | Secret extraction | Baseline pattern detection |
| T3 | Data exfiltration | Baseline pattern detection |
| T4 | Destructive action | Baseline pattern detection |
| T5 | Indirect prompt injection | Planned |
| T6 | Tool privilege escalation | Default-deny action policy baseline |
| T7 | Memory poisoning | Planned |
| T8 | Cross-agent injection | Planned |

## Explicit non-goals for v0.1

- Proving that an agent or model is safe.
- Detecting every natural-language attack or obfuscated payload.
- Replacing authentication, authorization, sandboxing, or human approval.
- Storing raw prompts by default.

## Known limitations

Pattern rules can be bypassed through paraphrasing, encoding, other languages,
or multi-step attacks. They can also produce false positives. The baseline is a
transparent enforcement signal and test harness, not a complete defense.

Policy enforcement depends on truthful context and action metadata supplied by
the host application. Hash chaining detects record modification but cannot by
itself detect removal or replacement of the entire audit chain. Sandboxing,
strong identity, least-privilege credentials, durable logs, and human approval
remain necessary controls.
