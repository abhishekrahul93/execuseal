# MCP Compatibility

The interception core targets the Model Context Protocol specification dated
`2026-07-28`, specifically JSON-RPC `tools/call` requests and complete tool
results with both text and structured content.

Reference: <https://modelcontextprotocol.io/specification/2026-07-28/server/tools>

Validated:

- JSON-RPC version, request ID, method, tool name and arguments
- required protocol version, client information and capability metadata
- `resultType: complete`, `content`, `structuredContent` and `isError` results
- locally trusted tool security profiles rather than untrusted annotations

Not yet implemented:

- transports, initialization, capability negotiation and subscriptions
- `tools/list`, pagination, caching and list-change notifications
- input-required multi-round-trip results
- JSON Schema validation of each tool's arguments and output
- cancellation and timeouts around downstream handlers

This module is an embeddable safety interceptor, not a complete MCP client or
server SDK. An official SDK transport adapter is planned after the enforcement
contract stabilizes.
