"""Short-lived, action-bound authorization tokens with replay protection."""

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import asdict, dataclass

from agent_safety_lab.actions import ActionContext, ToolAction
from agent_safety_lab.models import Action


class TokenError(ValueError):
    """Raised when an authorization token cannot be trusted."""


@dataclass(frozen=True, slots=True)
class AuthorizationClaims:
    version: int
    token_id: str
    action: str
    action_digest: str
    issued_at: int
    expires_at: int


class ReplayGuard:
    """Track consumed token IDs for one process, pruning expired entries."""

    def __init__(self) -> None:
        self._consumed: dict[str, int] = {}
        self._lock = threading.Lock()

    def consume(self, token_id: str, expires_at: int, now: int) -> None:
        with self._lock:
            self._consumed = {
                existing: expiry for existing, expiry in self._consumed.items() if expiry >= now
            }
            if token_id in self._consumed:
                raise TokenError("authorization token has already been consumed")
            self._consumed[token_id] = expires_at


class AuthorizationSigner:
    """Issue and verify compact HMAC tokens bound to exact action metadata."""

    def __init__(
        self,
        secret: str,
        ttl_seconds: int = 30,
        replay_guard: ReplayGuard | None = None,
    ) -> None:
        if len(secret.encode()) < 32:
            raise ValueError("signing secret must contain at least 32 bytes")
        if not 1 <= ttl_seconds <= 300:
            raise ValueError("token TTL must be between 1 and 300 seconds")
        self._secret = secret.encode()
        self._ttl_seconds = ttl_seconds
        self._replay_guard = replay_guard or ReplayGuard()

    def issue(
        self,
        action: ToolAction,
        context: ActionContext,
        decision: Action,
        now: int | None = None,
    ) -> str:
        if decision is not Action.ALLOW:
            raise TokenError("only allowed actions can receive authorization tokens")
        issued_at = int(time.time()) if now is None else now
        claims = AuthorizationClaims(
            version=1,
            token_id=secrets.token_urlsafe(18),
            action=decision.value,
            action_digest=_action_digest(action, context),
            issued_at=issued_at,
            expires_at=issued_at + self._ttl_seconds,
        )
        serialized = json.dumps(asdict(claims), sort_keys=True, separators=(",", ":"))
        payload = _encode(serialized.encode())
        signature = _encode(hmac.digest(self._secret, payload.encode(), "sha256"))
        return f"asl1.{payload}.{signature}"

    def verify_and_consume(
        self,
        token: str,
        action: ToolAction,
        context: ActionContext,
        now: int | None = None,
    ) -> AuthorizationClaims:
        current = int(time.time()) if now is None else now
        try:
            prefix, payload, supplied_signature = token.split(".")
        except ValueError as error:
            raise TokenError("malformed authorization token") from error
        if prefix != "asl1":
            raise TokenError("unsupported authorization token version")
        expected_signature = _encode(hmac.digest(self._secret, payload.encode(), "sha256"))
        if not hmac.compare_digest(supplied_signature, expected_signature):
            raise TokenError("invalid authorization token signature")
        try:
            raw = json.loads(_decode(payload))
            claims = AuthorizationClaims(**raw)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise TokenError("invalid authorization token claims") from error
        if claims.action != Action.ALLOW.value:
            raise TokenError("token does not authorize execution")
        if current < claims.issued_at - 5 or current >= claims.expires_at:
            raise TokenError("authorization token has expired or is not yet valid")
        if not hmac.compare_digest(claims.action_digest, _action_digest(action, context)):
            raise TokenError("authorization token does not match this action")
        self._replay_guard.consume(claims.token_id, claims.expires_at, current)
        return claims


def _action_digest(action: ToolAction, context: ActionContext) -> str:
    document = {
        "context": {
            "agent_id": context.agent_id,
            "principal_id": context.principal_id,
            "environment": context.environment.value,
        },
        "action": {
            "tool": action.tool,
            "operation": action.operation,
            "resource": action.resource,
            "data_classification": action.data_classification.name.lower(),
            "impact": action.impact.name.lower(),
            "external_destination": action.external_destination,
            "parameters": dict(action.parameters),
        },
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _decode(value: str) -> str:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding).decode()
