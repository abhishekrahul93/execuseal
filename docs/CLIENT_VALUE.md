# Client value and adoption guide

ExecuSeal helps teams control AI-agent actions before those actions reach a
database, API, file system, browser, email service, or MCP tool. It is useful
when an agent can cause real operational impact and a normal content filter is
not an adequate authorization boundary.

## Who benefits

| Team | Current risk | ExecuSeal contribution | Evidence to measure |
|---|---|---|---|
| AI product | Model can call tools outside intended scope | Default-deny action policy and exact-action tokens | Unauthorized calls prevented |
| Security | Prompt attacks may become real operations | Enforcement outside the model and replay rejection | Attack success rate |
| Compliance | Decisions are difficult to reconstruct | Data-minimized hash chain and signed checkpoints | Auditable decision coverage |
| Operations | High-impact actions need supervision | Blast-radius scoring and expiring human approval | Approval volume and response time |
| Platform engineering | Controls differ between agents | Provider-independent gateway and MCP interception | Integration time and policy reuse |
| Privacy | Prompts may contain secrets or PII | Deterministic detection and safe redaction | Sensitive-value detection and false positives |

ExecuSeal does not promise that an AI system is safe. Its value is narrower and
testable: proposed actions are checked against explicit policy, unsafe actions
can be stopped before execution, and the resulting decision can be verified and
audited.

## Try it in five minutes

Use only the checked-in synthetic data:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
execuseal demo
```

The demo shows four controls without credentials, network access, or external
tool execution:

1. an inventory read is allowed
2. a production inventory update pauses for review
3. an unknown customer export is blocked by default
4. a prompt containing synthetic PII and a synthetic secret is redacted

## Run a responsible pilot

1. Inventory the agent's tools, operations, resources, identities, and possible
   external destinations.
2. Begin in a non-production environment with synthetic data and a default-deny
   policy.
3. Replay representative allowed, review-required, and blocked actions.
4. Measure false positives, unsafe-call prevention, approval burden, p95
   authorization latency, and integration effort.
5. Review audit output and restore procedures with security and operations.
6. Expand scope gradually; retain sandboxing, least-privilege tool credentials,
   network controls, and human approval for destructive actions.

Do not send production secrets, personal data, or confidential prompts to a
public demo or issue tracker.

## Success criteria

A useful pilot defines targets before testing. Examples include zero downstream
execution for the agreed blocked scenarios, no token replay, complete audit
coverage for proposed tool actions, acceptable latency overhead, and a reviewed
false-positive budget. Publish measured results with dataset version, sample
size, environment, and limitations; never invent safety percentages.

## Give feedback

See [FEEDBACK.md](../FEEDBACK.md). Product feedback and false-positive examples
should use synthetic or redacted content. Suspected security vulnerabilities
must follow [SECURITY.md](../SECURITY.md), not a public issue.
