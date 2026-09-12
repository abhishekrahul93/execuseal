from collections.abc import Mapping
from typing import Any

from agent_safety_lab import (
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
from agent_safety_lab.mcp import McpSafetyProxy, McpToolProfile
from agent_safety_lab.tokens import AuthorizationSigner

SECRET = "test-signing-secret-with-more-than-32-bytes"


def build_proxy(executions: list[str]) -> McpSafetyProxy:
    profiles = (
        McpToolProfile(
            "inventory.read_stock",
            "read",
            "stock_levels",
            DataClassification.INTERNAL,
            Impact.NONE,
        ),
        McpToolProfile(
            "inventory.update_stock",
            "update",
            "stock_levels",
            DataClassification.INTERNAL,
            Impact.MULTIPLE_RECORDS,
        ),
        McpToolProfile(
            "inventory.export_customers",
            "export",
            "customer_records",
            DataClassification.RESTRICTED,
            Impact.MULTIPLE_RECORDS,
            external_destination=True,
        ),
    )
    policy = PolicySet(
        (
            PolicyRule(
                "block-export",
                Action.BLOCK,
                tools=frozenset({"inventory.export_customers"}),
                allow_external_destination=True,
            ),
            PolicyRule(
                "review-update",
                Action.REVIEW,
                tools=frozenset({"inventory.update_stock"}),
            ),
            PolicyRule(
                "allow-read",
                Action.ALLOW,
                tools=frozenset({"inventory.read_stock"}),
            ),
        )
    )

    def handler(arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        executions.append(str(arguments.get("sku", "executed")))
        return {"quantity": 42}

    handlers = {profile.name: handler for profile in profiles}
    return McpSafetyProxy(
        ActionFirewall(PolicyEngine(policy)),
        AuthorizationSigner(SECRET),
        profiles,
        handlers,
        AuditChain(),
    )


def request(name: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {"name": "test-client", "version": "1"},
            "io.modelcontextprotocol/clientCapabilities": {},
        },
        "params": {"name": name, "arguments": {"sku": "SKU-1"}},
    }


def context() -> ActionContext:
    return ActionContext("warehouse-agent", "operator-42", Environment.PRODUCTION)


def test_allowed_mcp_call_reaches_tool_once() -> None:
    executions: list[str] = []

    response = build_proxy(executions).call(request("inventory.read_stock"), context())

    result = response["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["executed"] is True
    assert result["structuredContent"]["output"] == {"quantity": 42}
    assert executions == ["SKU-1"]


def test_review_and_block_never_reach_tool() -> None:
    executions: list[str] = []
    proxy = build_proxy(executions)

    review = proxy.call(request("inventory.update_stock"), context())
    blocked = proxy.call(request("inventory.export_customers"), context())

    assert review["result"]["structuredContent"]["decision"] == "review"
    assert blocked["result"]["structuredContent"]["decision"] == "block"
    assert review["result"]["isError"] is True
    assert blocked["result"]["isError"] is True
    assert executions == []
