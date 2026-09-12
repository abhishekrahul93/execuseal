"""Safety interception for MCP 2026-07-28 `tools/call` requests."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol
from uuid import uuid4

from agent_safety_lab.actions import (
    ActionContext,
    DataClassification,
    Impact,
    ToolAction,
)
from agent_safety_lab.audit import AuditRecord
from agent_safety_lab.firewall import ActionDecision, ActionFirewall
from agent_safety_lab.tokens import AuthorizationSigner

McpToolHandler = Callable[[Mapping[str, Any]], Mapping[str, Any]]
MCP_PROTOCOL_VERSION = "2026-07-28"


class AuditSink(Protocol):
    def append(
        self,
        event_id: str,
        action: ToolAction,
        context: ActionContext,
        decision: ActionDecision,
        occurred_at: datetime | None = None,
    ) -> AuditRecord: ...


@dataclass(frozen=True, slots=True)
class McpToolProfile:
    name: str
    operation: str
    resource: str
    data_classification: DataClassification
    impact: Impact
    external_destination: bool = False


class McpRequestError(ValueError):
    """Raised when an MCP request is structurally invalid or unknown."""


class McpSafetyProxy:
    """Authorize MCP calls and invoke upstream only after token verification."""

    def __init__(
        self,
        firewall: ActionFirewall,
        signer: AuthorizationSigner,
        profiles: tuple[McpToolProfile, ...],
        handlers: Mapping[str, McpToolHandler],
        audit_sink: AuditSink,
    ) -> None:
        self._firewall = firewall
        self._signer = signer
        self._profiles = {profile.name: profile for profile in profiles}
        self._handlers = dict(handlers)
        self._audit_sink = audit_sink
        if set(self._handlers) != set(self._profiles):
            raise ValueError("every MCP tool profile must have exactly one handler")

    def call(self, request: Mapping[str, Any], context: ActionContext) -> dict[str, Any]:
        request_id, tool_name, arguments = _parse_call(request)
        profile = self._profiles.get(tool_name)
        if profile is None:
            raise McpRequestError(f"Unknown tool: {tool_name}")
        action = ToolAction(
            tool=profile.name,
            operation=profile.operation,
            resource=profile.resource,
            data_classification=profile.data_classification,
            impact=profile.impact,
            external_destination=profile.external_destination,
            parameters=_safe_parameters(arguments),
        )
        decision = self._firewall.authorize(action, context)
        audit = self._audit_sink.append(str(uuid4()), action, context, decision)
        if not decision.execution_allowed:
            return _tool_result(
                request_id,
                {
                    "executed": False,
                    "decision": decision.action.value,
                    "reason": decision.reason,
                    "policy_rule_id": decision.policy_rule_id,
                    "audit_hash": audit.record_hash,
                },
                is_error=True,
            )

        token = self._signer.issue(action, context, decision.action)
        self._signer.verify_and_consume(token, action, context)
        output = dict(self._handlers[tool_name](arguments))
        return _tool_result(
            request_id,
            {
                "executed": True,
                "decision": "allow",
                "audit_hash": audit.record_hash,
                "output": output,
            },
            is_error=False,
        )


def _parse_call(request: Mapping[str, Any]) -> tuple[str | int, str, Mapping[str, Any]]:
    if request.get("jsonrpc") != "2.0" or request.get("method") != "tools/call":
        raise McpRequestError("Expected a JSON-RPC 2.0 tools/call request")
    metadata = request.get("_meta")
    if not isinstance(metadata, Mapping):
        raise McpRequestError("MCP request must include protocol metadata")
    if metadata.get("io.modelcontextprotocol/protocolVersion") != MCP_PROTOCOL_VERSION:
        raise McpRequestError(f"MCP protocol version must be {MCP_PROTOCOL_VERSION}")
    if not isinstance(metadata.get("io.modelcontextprotocol/clientInfo"), Mapping):
        raise McpRequestError("MCP metadata must include clientInfo")
    if not isinstance(metadata.get("io.modelcontextprotocol/clientCapabilities"), Mapping):
        raise McpRequestError("MCP metadata must include clientCapabilities")
    request_id = request.get("id")
    if not isinstance(request_id, (str, int)) or isinstance(request_id, bool):
        raise McpRequestError("MCP request id must be a string or integer")
    params = request.get("params")
    if not isinstance(params, Mapping):
        raise McpRequestError("MCP params must be an object")
    name = params.get("name")
    arguments = params.get("arguments", {})
    if not isinstance(name, str) or not name or len(name) > 128:
        raise McpRequestError("MCP tool name must contain 1 to 128 characters")
    if not isinstance(arguments, Mapping):
        raise McpRequestError("MCP tool arguments must be an object")
    return request_id, name, arguments


def _safe_parameters(arguments: Mapping[str, Any]) -> dict[str, str | int | bool]:
    safe: dict[str, str | int | bool] = {}
    for key, value in arguments.items():
        if not isinstance(key, str) or not isinstance(value, (str, int, bool)):
            continue
        safe[key] = value
    return safe


def _tool_result(
    request_id: str | int,
    structured: dict[str, Any],
    is_error: bool,
) -> dict[str, Any]:
    import json

    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "resultType": "complete",
            "content": [{"type": "text", "text": json.dumps(structured, sort_keys=True)}],
            "structuredContent": structured,
            "isError": is_error,
        },
    }
