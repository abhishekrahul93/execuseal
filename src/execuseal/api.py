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
from execuseal.approvals import (
    ApprovalError,
    ApprovalRequest,
    ApprovalStatus,
    SqlApprovalStore,
)
from execuseal.audit_store import SqlAuditStore
from execuseal.config import load_policy
from execuseal.engine import SafetyEngine
from execuseal.firewall import ActionFirewall
from execuseal.models import Action
from execuseal.policy import PolicyEngine
from execuseal.rate_limit import RateLimiter
from execuseal.tokens import AuthorizationSigner, SqlReplayGuard, action_digest

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
    signing_keys_json: str = (
        '{"development":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}'
    )
    active_signing_key_id: str = "development"
    token_ttl_seconds: int = 30
    reviewer_api_keys: tuple[str, ...] = ()
    approval_ttl_seconds: int = 900

    def __post_init__(self) -> None:
        if not self.api_keys or any(len(key) < 16 for key in self.api_keys):
            raise ValueError("At least one API key of 16 or more characters is required")
        if len(set(self.api_keys)) != len(self.api_keys):
            raise ValueError("API keys must be unique")
        if self.deployment_environment == "production" and not self.database_url.startswith(
            ("postgresql://", "postgresql+psycopg://")
        ):
            raise ValueError("Production requires a PostgreSQL database URL")
        signing_keys = self.signing_keys()
        if self.active_signing_key_id not in signing_keys:
            raise ValueError("Active signing key is not present in the key ring")
        if self.deployment_environment == "production" and self.active_signing_key_id == (
            "development"
        ):
            raise ValueError("Production requires a non-development signing key")
        if any(len(key) < 16 for key in self.reviewer_api_keys):
            raise ValueError("Reviewer API keys must contain 16 or more characters")
        if len(set(self.reviewer_api_keys)) != len(self.reviewer_api_keys):
            raise ValueError("Reviewer API keys must be unique")
        if set(self.api_keys) & set(self.reviewer_api_keys):
            raise ValueError("Agent and reviewer API keys must be separate")
        if self.deployment_environment == "production" and not self.reviewer_api_keys:
            raise ValueError("Production requires at least one reviewer API key")
        if not 30 <= self.approval_ttl_seconds <= 86_400:
            raise ValueError("Approval TTL must be between 30 and 86400 seconds")

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
            os.getenv("EXECUSEAL_SIGNING_KEYS_JSON", "{}"),
            os.getenv("EXECUSEAL_ACTIVE_SIGNING_KEY_ID", ""),
            int(os.getenv("EXECUSEAL_TOKEN_TTL_SECONDS", "30")),
            tuple(
                key.strip()
                for key in os.getenv("EXECUSEAL_REVIEWER_API_KEYS", "").split(",")
                if key.strip()
            ),
            int(os.getenv("EXECUSEAL_APPROVAL_TTL_SECONDS", "900")),
        )

    def signing_keys(self) -> dict[str, str]:
        try:
            raw = json.loads(self.signing_keys_json)
        except json.JSONDecodeError as error:
            raise ValueError("Signing key ring must be a JSON object") from error
        if not isinstance(raw, dict) or not raw:
            raise ValueError("Signing key ring must be a non-empty JSON object")
        invalid_entry = any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in raw.items()
        )
        if invalid_entry:
            raise ValueError("Signing key IDs and values must be strings")
        return raw


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
    approval_id: str | None
    approval_expires_at: str | None


class ApprovalDecisionRequest(StrictModel):
    context: ContextRequest
    action: ToolActionRequest
    decision: Literal["approved", "rejected"]
    reason: str = Field(min_length=1, max_length=512)


class ApprovalResponse(StrictModel):
    approval_id: str
    status: str
    agent_id: str
    principal_id: str
    tool: str
    operation: str
    resource: str
    created_at: str
    expires_at: str
    decided_at: str | None
    reviewer_id: str | None
    reason: str | None
    authorization_token: str | None = None


class StatusResponse(StrictModel):
    status: str
    version: str
    api_version: str


class VerificationKeysResponse(StrictModel):
    algorithm: str
    active_key_id: str
    keys: dict[str, str]


@dataclass(slots=True)
class GatewayState:
    prompt_engine: SafetyEngine
    action_firewall: ActionFirewall
    audit_store: SqlAuditStore
    approval_store: SqlApprovalStore
    rate_limiter: RateLimiter
    signer: AuthorizationSigner


api_key_header = APIKeyHeader(
    name="X-API-Key",
    scheme_name="AgentApiKey",
    auto_error=False,
)
reviewer_key_header = APIKeyHeader(
    name="X-Reviewer-Key",
    scheme_name="ReviewerApiKey",
    auto_error=False,
)


def create_app(settings: GatewaySettings | None = None) -> FastAPI:
    """Build a fully configured gateway; fail startup on invalid policy or secrets."""

    active_settings = settings or GatewaySettings.from_environment()
    policy = load_policy(active_settings.policy_path)
    audit_store = SqlAuditStore(active_settings.database_url)
    audit_store.initialize()
    approval_store = SqlApprovalStore(
        active_settings.database_url,
        active_settings.approval_ttl_seconds,
    )
    approval_store.initialize()
    replay_guard = SqlReplayGuard(active_settings.database_url)
    replay_guard.initialize()
    gateway = GatewayState(
        prompt_engine=SafetyEngine(),
        action_firewall=ActionFirewall(PolicyEngine(policy)),
        audit_store=audit_store,
        approval_store=approval_store,
        rate_limiter=RateLimiter(
            active_settings.rate_limit_requests,
            active_settings.rate_limit_window_seconds,
        ),
        signer=AuthorizationSigner.from_base64_keys(
            active_settings.signing_keys(),
            active_settings.active_signing_key_id,
            replay_guard,
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

    def require_reviewer_key(key: str | None = Security(reviewer_key_header)) -> str:
        valid_key = key is not None and any(
            hmac.compare_digest(key, valid) for valid in active_settings.reviewer_api_keys
        )
        if not valid_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing reviewer key",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        assert key is not None
        reviewer_id = hashlib.sha256(key.encode()).hexdigest()[:16]
        allowed, _remaining = gateway.rate_limiter.allow(f"reviewer:{reviewer_id}")
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(active_settings.rate_limit_window_seconds)},
            )
        return reviewer_id

    @app.get("/healthz", response_model=StatusResponse, tags=["operations"])
    def health() -> StatusResponse:
        return StatusResponse(status="ok", version=PACKAGE_VERSION, api_version=API_VERSION)

    @app.get("/readyz", response_model=StatusResponse, tags=["operations"])
    def ready() -> StatusResponse:
        if not gateway.audit_store.verify():
            raise HTTPException(status_code=503, detail="Audit chain verification failed")
        return StatusResponse(status="ready", version=PACKAGE_VERSION, api_version=API_VERSION)

    @app.get(
        "/.well-known/execuseal-keys.json",
        response_model=VerificationKeysResponse,
        tags=["operations"],
    )
    def verification_keys() -> VerificationKeysResponse:
        return VerificationKeysResponse(
            algorithm="Ed25519",
            active_key_id=active_settings.active_signing_key_id,
            keys=gateway.signer.public_keys_base64(),
        )

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
        context, action = _domain_action(payload.context, payload.action)
        decision = gateway.action_firewall.authorize(action, context)
        audit = gateway.audit_store.append(
            str(uuid.uuid4()),
            action,
            context,
            decision,
        )
        approval = (
            gateway.approval_store.create(
                str(uuid.uuid4()),
                action_digest(action, context),
                context.agent_id,
                context.principal_id,
                action.tool,
                action.operation,
                action.resource,
            )
            if decision.approval_required
            else None
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
            approval_id=approval.approval_id if approval else None,
            approval_expires_at=approval.expires_at if approval else None,
        )

    @app.get(
        "/v1/approvals/{approval_id}",
        response_model=ApprovalResponse,
        tags=["approvals"],
    )
    def get_approval(
        approval_id: str,
        _reviewer_id: str = Depends(require_reviewer_key),
    ) -> ApprovalResponse:
        approval = gateway.approval_store.get(approval_id)
        if approval is None:
            raise HTTPException(status_code=404, detail="Approval request not found")
        return _approval_response(approval)

    @app.post(
        "/v1/approvals/{approval_id}/decision",
        response_model=ApprovalResponse,
        tags=["approvals"],
    )
    def decide_approval(
        approval_id: str,
        payload: ApprovalDecisionRequest,
        reviewer_id: str = Depends(require_reviewer_key),
    ) -> ApprovalResponse:
        context, action = _domain_action(payload.context, payload.action)
        try:
            approval = gateway.approval_store.decide(
                approval_id,
                action_digest(action, context),
                reviewer_id,
                ApprovalStatus(payload.decision),
                payload.reason,
            )
        except ApprovalError as error:
            message = str(error)
            code = 404 if message == "approval request not found" else 409
            raise HTTPException(status_code=code, detail=message) from error
        token = (
            gateway.signer.issue(action, context, Action.ALLOW)
            if approval.status is ApprovalStatus.APPROVED
            else None
        )
        return _approval_response(approval, token)

    return app


def _valid_request_id(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= 128
        and all(character.isalnum() or character in "-_." for character in value)
    )


def _domain_action(
    context: ContextRequest,
    action: ToolActionRequest,
) -> tuple[ActionContext, ToolAction]:
    return (
        ActionContext(context.agent_id, context.principal_id, context.environment),
        ToolAction(
            action.tool,
            action.operation,
            action.resource,
            DataClassification[action.data_classification.upper()],
            Impact[action.impact.upper()],
            action.external_destination,
            action.parameters,
        ),
    )


def _approval_response(
    approval: ApprovalRequest,
    token: str | None = None,
) -> ApprovalResponse:
    return ApprovalResponse(
        approval_id=approval.approval_id,
        status=approval.status.value,
        agent_id=approval.agent_id,
        principal_id=approval.principal_id,
        tool=approval.tool,
        operation=approval.operation,
        resource=approval.resource,
        created_at=approval.created_at,
        expires_at=approval.expires_at,
        decided_at=approval.decided_at,
        reviewer_id=approval.reviewer_id,
        reason=approval.reason,
        authorization_token=token,
    )
