"""Ed25519 action tokens with key rotation and durable replay protection."""

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import asdict, dataclass
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine, delete
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from execuseal.actions import ActionContext, ToolAction
from execuseal.models import Action

TOKEN_ISSUER = "execuseal"
TOKEN_AUDIENCE = "tool-execution"
KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

metadata = MetaData()
consumed_tokens = Table(
    "consumed_tokens",
    metadata,
    Column("token_id", String(128), primary_key=True),
    Column("expires_at", Integer, nullable=False),
)


class TokenError(ValueError):
    """Raised when an authorization token cannot be trusted."""


@dataclass(frozen=True, slots=True)
class AuthorizationClaims:
    version: int
    token_id: str
    issuer: str
    audience: str
    action: str
    action_digest: str
    issued_at: int
    expires_at: int


class ReplayGuard(Protocol):
    def consume(self, token_id: str, expires_at: int, now: int) -> None: ...


class SqlReplayGuard:
    """Atomically reject token reuse across processes and application restarts."""

    def __init__(self, database_url: str) -> None:
        self.engine: Engine = create_engine(database_url, pool_pre_ping=True)

    def initialize(self) -> None:
        metadata.create_all(self.engine)

    def consume(self, token_id: str, expires_at: int, now: int) -> None:
        try:
            with self.engine.begin() as connection:
                connection.execute(
                    delete(consumed_tokens).where(consumed_tokens.c.expires_at < now)
                )
                connection.execute(
                    consumed_tokens.insert().values(token_id=token_id, expires_at=expires_at)
                )
        except IntegrityError as error:
            raise TokenError("authorization token has already been consumed") from error

    def close(self) -> None:
        self.engine.dispose()


class AuthorizationVerifier:
    """Verify tokens using public keys only and consume them exactly once."""

    def __init__(
        self,
        public_keys: dict[str, Ed25519PublicKey],
        replay_guard: ReplayGuard,
    ) -> None:
        if not public_keys:
            raise ValueError("at least one verification key is required")
        if any(not KEY_ID_PATTERN.fullmatch(key_id) for key_id in public_keys):
            raise ValueError("invalid verification key ID")
        self._public_keys = dict(public_keys)
        self._replay_guard = replay_guard

    def verify_and_consume(
        self,
        token: str,
        action: ToolAction,
        context: ActionContext,
        now: int | None = None,
    ) -> AuthorizationClaims:
        current = int(time.time()) if now is None else now
        try:
            prefix, key_id, payload, supplied_signature = token.split(".")
        except ValueError as error:
            raise TokenError("malformed authorization token") from error
        if prefix != "exs2":
            raise TokenError("unsupported authorization token version")
        public_key = self._public_keys.get(key_id)
        if public_key is None:
            raise TokenError("unknown authorization signing key")
        try:
            public_key.verify(_decode_bytes(supplied_signature), _signed_message(key_id, payload))
        except (InvalidSignature, ValueError) as error:
            raise TokenError("invalid authorization token signature") from error
        try:
            raw = json.loads(_decode_bytes(payload))
            claims = AuthorizationClaims(**raw)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise TokenError("invalid authorization token claims") from error
        if claims.version != 2 or claims.issuer != TOKEN_ISSUER:
            raise TokenError("invalid authorization token issuer or version")
        if claims.audience != TOKEN_AUDIENCE:
            raise TokenError("invalid authorization token audience")
        if claims.action != Action.ALLOW.value:
            raise TokenError("token does not authorize execution")
        if current < claims.issued_at - 5 or current >= claims.expires_at:
            raise TokenError("authorization token has expired or is not yet valid")
        if not hmac.compare_digest(claims.action_digest, action_digest(action, context)):
            raise TokenError("authorization token does not match this action")
        self._replay_guard.consume(claims.token_id, claims.expires_at, current)
        return claims


class AuthorizationSigner:
    """Sign with the active Ed25519 key and verify against a rotating key ring."""

    def __init__(
        self,
        private_keys: dict[str, Ed25519PrivateKey],
        active_key_id: str,
        replay_guard: ReplayGuard,
        ttl_seconds: int = 30,
    ) -> None:
        if active_key_id not in private_keys:
            raise ValueError("active signing key is not present in the key ring")
        if not KEY_ID_PATTERN.fullmatch(active_key_id):
            raise ValueError("invalid active signing key ID")
        if not 1 <= ttl_seconds <= 300:
            raise ValueError("token TTL must be between 1 and 300 seconds")
        self._private_keys = dict(private_keys)
        self._active_key_id = active_key_id
        self._ttl_seconds = ttl_seconds
        self.verifier = AuthorizationVerifier(
            {key_id: key.public_key() for key_id, key in private_keys.items()},
            replay_guard,
        )

    @classmethod
    def from_base64_keys(
        cls,
        encoded_keys: dict[str, str],
        active_key_id: str,
        replay_guard: ReplayGuard,
        ttl_seconds: int = 30,
    ) -> "AuthorizationSigner":
        try:
            keys = {
                key_id: Ed25519PrivateKey.from_private_bytes(_decode_standard(value))
                for key_id, value in encoded_keys.items()
            }
        except (TypeError, ValueError) as error:
            raise ValueError("signing keys must be base64-encoded 32-byte Ed25519 keys") from error
        return cls(keys, active_key_id, replay_guard, ttl_seconds)

    def public_keys_base64(self) -> dict[str, str]:
        return {
            key_id: base64.b64encode(
                key.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
            ).decode()
            for key_id, key in self._private_keys.items()
        }

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
            version=2,
            token_id=secrets.token_urlsafe(18),
            issuer=TOKEN_ISSUER,
            audience=TOKEN_AUDIENCE,
            action=decision.value,
            action_digest=action_digest(action, context),
            issued_at=issued_at,
            expires_at=issued_at + self._ttl_seconds,
        )
        payload = _encode(
            json.dumps(asdict(claims), sort_keys=True, separators=(",", ":")).encode()
        )
        signature = self._private_keys[self._active_key_id].sign(
            _signed_message(self._active_key_id, payload)
        )
        return f"exs2.{self._active_key_id}.{payload}.{_encode(signature)}"

    def verify_and_consume(
        self,
        token: str,
        action: ToolAction,
        context: ActionContext,
        now: int | None = None,
    ) -> AuthorizationClaims:
        return self.verifier.verify_and_consume(token, action, context, now)


def action_digest(action: ToolAction, context: ActionContext) -> str:
    """Return the canonical identity digest used by approvals and tokens."""
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


def public_keys_from_base64(encoded_keys: dict[str, str]) -> dict[str, Ed25519PublicKey]:
    """Build a verification ring suitable for a separate tool executor."""
    try:
        return {
            key_id: Ed25519PublicKey.from_public_bytes(_decode_standard(value))
            for key_id, value in encoded_keys.items()
        }
    except (TypeError, ValueError) as error:
        raise ValueError("verification keys must be base64-encoded 32-byte Ed25519 keys") from error


def _signed_message(key_id: str, payload: str) -> bytes:
    return f"exs2.{key_id}.{payload}".encode()


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _decode_bytes(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _decode_standard(value: str) -> bytes:
    decoded = base64.b64decode(value, validate=True)
    if len(decoded) != 32:
        raise ValueError("Ed25519 keys must contain exactly 32 bytes")
    return decoded
