# Integrate ExecuSeal in five minutes

This guide shows the smallest safe integration pattern. ExecuSeal decides
whether a proposed action may proceed; your application remains responsible for
executing the action with least-privilege credentials.

## 1. See the behavior without installing anything

Open the [public sandbox](https://execuseal.onrender.com/playground). It uses
fixed synthetic data, requires no credentials, stores no proposed action, and
never calls a real tool.

Expected outcomes:

| Proposed action | Decision | Why |
|---|---|---|
| Read inventory | `allow` | Routine read covered by policy |
| Update production inventory | `review` | Multi-record production write |
| Export customer records | `block` | Restricted data and external destination |

## 2. Run a private local gateway

```bash
git clone https://github.com/abhishekrahul93/execuseal.git
cd execuseal
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -e .
```

Create a long random development key and start the service:

```bash
export EXECUSEAL_API_KEYS="replace-with-at-least-16-random-characters"
export EXECUSEAL_POLICY_PATH="policies/warehouse.yml"
uvicorn execuseal.api:create_app --factory --host 127.0.0.1 --port 8000
```

PowerShell uses `$env:EXECUSEAL_API_KEYS="..."` and
`$env:EXECUSEAL_POLICY_PATH="policies/warehouse.yml"`.

## 3. Ask before an agent acts

Send trusted agent context and the proposed tool action to the gateway:

```bash
curl -s http://127.0.0.1:8000/v1/actions/authorize \
  -H "X-API-Key: $EXECUSEAL_API_KEYS" \
  -H "Content-Type: application/json" \
  -d '{
    "context": {
      "agent_id": "warehouse-agent",
      "principal_id": "operator-42",
      "environment": "production"
    },
    "action": {
      "tool": "inventory_db",
      "operation": "update",
      "resource": "stock_levels",
      "impact": "multiple_records",
      "parameters": {"sku": "DEMO-001", "quantity": 12}
    }
  }'
```

Do not derive identity, environment, permissions, or data classification from
model output. Supply them from your authenticated application and tool registry.

## 4. Enforce the decision in the host

The critical rule is simple: no tool call happens before authorization.

```python
decision = execuseal.authorize(context=trusted_context, action=proposed_action)

if decision.action == "block":
    raise PermissionError(decision.reason)

if decision.action == "review":
    return queue_for_human_approval(decision.approval_id)

if decision.action == "allow":
    verify_and_consume(decision.authorization_token, proposed_action)
    return tool.execute(**proposed_action.parameters)
```

This pseudocode intentionally makes execution a separate step. The executor
must verify that the signed token matches the exact action and consume it once;
an `allow` string by itself is not authorization.

## 5. Pilot safely

- start with synthetic data and a non-production tool account
- route every proposed action through the gateway
- use default-deny policy and least-privilege executor credentials
- keep reviewer, agent, admin, and metrics keys separate
- measure blocked unsafe calls, false positives, approval burden, and p95 latency
- retain signed audit checkpoints outside the database trust boundary

Read [CLIENT_VALUE.md](CLIENT_VALUE.md) for pilot success criteria and
[SECURITY.md](../SECURITY.md) before considering a production deployment.

## What ExecuSeal does not do

ExecuSeal does not make a model safe, replace sandboxing or network controls,
or guarantee detection of every attack. The current release is pre-alpha. The
checked-in 38-case synthetic benchmark is for regression tracking, not a
real-world safety-success claim.
