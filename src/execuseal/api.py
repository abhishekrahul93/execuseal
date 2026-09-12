"""Authenticated FastAPI gateway for pre-execution AI-agent safety checks."""

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Response, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.base import RequestResponseEndpoint

from execuseal.actions import (
    ActionContext,
    DataClassification,
    Environment,
    Impact,
    ToolAction,
)
from execuseal.audit_store import SqlAuditStore
from execuseal.config import load_policy
from execuseal.engine import SafetyEngine
from execuseal.firewall import ActionFirewall
from execuseal.policy import PolicyEngine
from execuseal.rate_limit import RateLimiter
from execuseal.tokens import AuthorizationSigner

API_VERSION = "v1"
PACKAGE_VERSION = "0.1.0a0"
MAX_INPUT_LENGTH = 100_000
MAX_METADATA_FIELDS = 32


@dataclass(frozen=True, slots=True)
class GatewaySettings:
    """Validated runtime configuration. Secrets are never returned by the API."""

    api_keys: tuple[str, ...]
    policy_path: Path
    cors_origins: tuple[str, ...] = ()
    database_url: str = "sqlite:///execuseal.db"
    rate_limit_requests: int = 120
    rate_limit_window_seconds: int = 60
    deployment_environment: str = "development"
    signing_secret: str = "development-signing-secret-change-me-32-bytes"
    token_ttl_seconds: int = 30

    def __post_init__(self) -> None:
        if not self.api_keys or any(len(key) < 16 for key in self.api_keys):
            raise ValueError("At least one API key of 16 or more characters is required")
        if len(set(self.api_keys)) != len(self.api_keys):
            raise ValueError("API keys must be unique")
        if self.deployment_environment == "production" and not self.database_url.startswith(
            ("postgresql://", "postgresql+psycopg://")
        ):
            raise ValueError("Production requires a PostgreSQL database URL")
        if len(self.signing_secret.encode()) < 32:
            raise ValueError("Signing secret must contain at least 32 bytes")
        if self.deployment_environment == "production" and self.signing_secret.startswith(
            "development-"
        ):
            raise ValueError("Production requires a non-development signing secret")

    @classmethod
    def from_environment(cls) -> "GatewaySettings":
        keys = tuple(
            key.strip()
            for key in os.getenv("EXECUSEAL_API_KEYS", "").split(",")
            if key.strip()
        )
        policy_path = Path(os.getenv("EXECUSEAL_POLICY_PATH", "policies/warehouse.yml"))
        origins = tuple(
            origin.strip()
            for origin in os.getenv("EXECUSEAL_CORS_ORIGINS", "").split(",")
            if origin.strip()
        )
        return cls(
            keys,
            policy_path,
            origins,
            os.getenv("EXECUSEAL_DATABASE_URL", "sqlite:///execuseal.db"),
            int(os.getenv("EXECUSEAL_RATE_LIMIT_REQUESTS", "120")),
            int(os.getenv("EXECUSEAL_RATE_LIMIT_WINDOW_SECONDS", "60")),
            os.getenv("EXECUSEAL_ENVIRONMENT", "development"),
            os.getenv("EXECUSEAL_SIGNING_SECRET", ""),
            int(os.getenv("EXECUSEAL_TOKEN_TTL_SECONDS", "30")),
        )


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScanRequest(StrictModel):
    text: str = Field(min_length=1, max_length=MAX_INPUT_LENGTH)


class FindingResponse(StrictModel):
    rule_id: str
    category: str
    severity: int = Field(ge=0, le=100)
    description: str


class ScanResponse(StrictModel):
    request_id: str
    action: str
    risk_score: int = Field(ge=0, le=100)
    findings: list[FindingResponse]


class ContextRequest(StrictModel):
    agent_id: str = Field(min_length=1, max_length=128)
    principal_id: str = Field(min_length=1, max_length=128)
    environment: Environment


class ToolActionRequest(StrictModel):
    tool: str = Field(min_length=1, max_length=128)
    operation: str = Field(min_length=1, max_length=128)
    resource: str = Field(min_length=1, max_length=512)
    data_classification: Literal["public", "internal", "confidential", "restricted"] = "internal"
    impact: Literal["none", "single_record", "multiple_records", "system_wide"] = "none"
    external_destination: bool = False
    parameters: dict[str, str | int | bool] = Field(
        default_factory=dict,
        max_length=MAX_METADATA_FIELDS,
    )


class AuthorizeRequest(StrictModel):
    context: ContextRequest
    action: ToolActionRequest


class BlastRadiusResponse(StrictModel):
    score: int = Field(ge=0, le=100)
    level: str
    reasons: list[str]


class AuthorizeResponse(StrictModel):
    request_id: str
    action: str
    execution_allowed: bool
    approval_required: bool
    policy_rule_id: str | None
    reason: str
    blast_radius: BlastRadiusResponse
    audit_hash: str
    authorization_token: str | None


class StatusResponse(StrictModel):
    status: str
    version: str
    api_version: str


@dataclass(slots=True)
class GatewayState:
    prompt_engine: SafetyEngine
    action_firewall: ActionFirewall
    audit_store: SqlAuditStore
    rate_limiter: RateLimiter
    signer: AuthorizationSigner


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def create_app(settings: GatewaySettings | None = None) -> FastAPI:
    """Build a fully configured gateway; fail startup on invalid policy or secrets."""

    active_settings = settings or GatewaySettings.from_environment()
    policy = load_policy(active_settings.policy_path)
    audit_store = SqlAuditStore(active_settings.database_url)
    audit_store.initialize()
    gateway = GatewayState(
        prompt_engine=SafetyEngine(),
        action_firewall=ActionFirewall(PolicyEngine(policy)),
        audit_store=audit_store,
        rate_limiter=RateLimiter(
            active_settings.rate_limit_requests,
            active_settings.rate_limit_window_seconds,
        ),
        signer=AuthorizationSigner(
            active_settings.signing_secret,
            active_settings.token_ttl_seconds,
        ),
    )
    app = FastAPI(
        title="ExecuSeal Gateway",
        description="Pre-execution policy firewall for AI-agent prompts and tool actions.",
        version=PACKAGE_VERSION,
        docs_url="/docs",
        redoc_url=None,
    )
    app.state.gateway = gateway
    app.state.settings = active_settings

    if active_settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(active_settings.cors_origins),
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type", "X-API-Key", "X-Request-ID"],
        )

    @app.middleware("http")
    async def request_id_middleware(
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        supplied = request.headers.get("X-Request-ID", "")
        request_id = supplied if _valid_request_id(supplied) else str(uuid.uuid4())
        request.state.request_id = request_id
        started = time.perf_counter()
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        logging.getLogger("execuseal.request").info(
            json.dumps(
                {
                    "event": "http_request",
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                },
                separators=(",", ":"),
            )
        )
        return response

    def require_api_key(key: str | None = Security(api_key_header)) -> None:
        valid_key = key is not None and any(
            hmac.compare_digest(key, valid) for valid in active_settings.api_keys
        )
        if not valid_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        assert key is not None
        key_identity = hashlib.sha256(key.encode()).hexdigest()[:16]
        allowed, _remaining = gateway.rate_limiter.allow(key_identity)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(active_settings.rate_limit_window_seconds)},
            )

    @app.get("/healthz", response_model=StatusResponse, tags=["operations"])
    def health() -> StatusResponse:
        return StatusResponse(status="ok", version=PACKAGE_VERSION, api_version=API_VERSION)

    @app.get("/readyz", response_model=StatusResponse, tags=["operations"])
    def ready() -> StatusResponse:
        if not gateway.audit_store.verify():
            raise HTTPException(status_code=503, detail="Audit chain verification failed")
        return StatusResponse(status="ready", version=PACKAGE_VERSION, api_version=API_VERSION)

    @app.post(
        "/v1/scan",
        response_model=ScanResponse,
        dependencies=[Depends(require_api_key)],
        tags=["safety"],
    )
    def scan(payload: ScanRequest, request: Request) -> ScanResponse:
        decision = gateway.prompt_engine.evaluate(payload.text)
        return ScanResponse(
            request_id=request.state.request_id,
            action=decision.action.value,
            risk_score=decision.risk_score,
            findings=[
                FindingResponse(
                    rule_id=finding.rule_id,
                    category=finding.category,
                    severity=finding.severity,
                    description=finding.description,
                )
                for finding in decision.findings
            ],
        )

    @app.post(
        "/v1/actions/authorize",
        response_model=AuthorizeResponse,
        dependencies=[Depends(require_api_key)],
        tags=["actions"],
    )
    def authorize(payload: AuthorizeRequest, request: Request) -> AuthorizeResponse:
        context = ActionContext(
            payload.context.agent_id,
            payload.context.principal_id,
            payload.context.environment,
        )
        action = ToolAction(
            payload.action.tool,
            payload.action.operation,
            payload.action.resource,
            DataClassification[payload.action.data_classification.upper()],
            Impact[payload.action.impact.upper()],
            payload.action.external_destination,
            payload.action.parameters,
        )
        decision = gateway.action_firewall.authorize(action, context)
        audit = gateway.audit_store.append(
            str(uuid.uuid4()),
            action,
            context,
            decision,
        )
        return AuthorizeResponse(
            request_id=request.state.request_id,
            action=decision.action.value,
            execution_allowed=decision.execution_allowed,
            approval_required=decision.approval_required,
            policy_rule_id=decision.policy_rule_id,
            reason=decision.reason,
            blast_radius=BlastRadiusResponse(
                score=decision.blast_radius.score,
                level=decision.blast_radius.level,
                reasons=list(decision.blast_radius.reasons),
            ),
            audit_hash=audit.record_hash,
            authorization_token=(
                gateway.signer.issue(action, context, decision.action)
                if decision.execution_allowed
                else None
            ),
        )

    return app


def _valid_request_id(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= 128
        and all(character.isalnum() or character in "-_." for character in value)
    )
