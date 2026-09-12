"""Persistent, expiring human approval requests with atomic decisions."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from sqlalchemy import Column, MetaData, String, Table, create_engine, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.engine.row import RowMapping

metadata = MetaData()
approval_requests = Table(
    "approval_requests",
    metadata,
    Column("approval_id", String(128), primary_key=True),
    Column("action_digest", String(64), nullable=False),
    Column("agent_id", String(128), nullable=False),
    Column("principal_id", String(128), nullable=False),
    Column("tool", String(128), nullable=False),
    Column("operation", String(128), nullable=False),
    Column("resource", String(512), nullable=False),
    Column("status", String(16), nullable=False),
    Column("created_at", String(64), nullable=False),
    Column("expires_at", String(64), nullable=False),
    Column("decided_at", String(64), nullable=True),
    Column("reviewer_id", String(128), nullable=True),
    Column("reason", String(512), nullable=True),
)


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ApprovalError(ValueError):
    """Raised when an approval transition is invalid or unsafe."""


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    approval_id: str
    action_digest: str
    agent_id: str
    principal_id: str
    tool: str
    operation: str
    resource: str
    status: ApprovalStatus
    created_at: str
    expires_at: str
    decided_at: str | None = None
    reviewer_id: str | None = None
    reason: str | None = None


class SqlApprovalStore:
    """Store approval metadata without retaining action parameters."""

    def __init__(self, database_url: str, ttl_seconds: int = 900) -> None:
        if not 30 <= ttl_seconds <= 86_400:
            raise ValueError("approval TTL must be between 30 and 86400 seconds")
        self.engine: Engine = create_engine(database_url, pool_pre_ping=True)
        self._ttl_seconds = ttl_seconds

    def initialize(self) -> None:
        metadata.create_all(self.engine)

    def create(
        self,
        approval_id: str,
        action_digest: str,
        agent_id: str,
        principal_id: str,
        tool: str,
        operation: str,
        resource: str,
        now: datetime | None = None,
    ) -> ApprovalRequest:
        created = _utc(now)
        record = ApprovalRequest(
            approval_id=approval_id,
            action_digest=action_digest,
            agent_id=agent_id,
            principal_id=principal_id,
            tool=tool,
            operation=operation,
            resource=resource,
            status=ApprovalStatus.PENDING,
            created_at=created.isoformat(),
            expires_at=(created + timedelta(seconds=self._ttl_seconds)).isoformat(),
        )
        with self.engine.begin() as connection:
            connection.execute(approval_requests.insert().values(**_values(record)))
        return record

    def get(self, approval_id: str, now: datetime | None = None) -> ApprovalRequest | None:
        current = _utc(now)
        with self.engine.begin() as connection:
            row = connection.execute(
                select(approval_requests).where(approval_requests.c.approval_id == approval_id)
            ).mappings().one_or_none()
            if row is None:
                return None
            record = _record(row)
            if record.status is ApprovalStatus.PENDING and current >= datetime.fromisoformat(
                record.expires_at
            ):
                connection.execute(
                    update(approval_requests)
                    .where(approval_requests.c.approval_id == approval_id)
                    .where(approval_requests.c.status == ApprovalStatus.PENDING.value)
                    .values(status=ApprovalStatus.EXPIRED.value)
                )
                return _replace_status(record, ApprovalStatus.EXPIRED)
            return record

    def decide(
        self,
        approval_id: str,
        action_digest: str,
        reviewer_id: str,
        decision: ApprovalStatus,
        reason: str,
        now: datetime | None = None,
    ) -> ApprovalRequest:
        if decision not in (ApprovalStatus.APPROVED, ApprovalStatus.REJECTED):
            raise ApprovalError("decision must be approved or rejected")
        current = _utc(now)
        with self.engine.begin() as connection:
            result = connection.execute(
                update(approval_requests)
                .where(approval_requests.c.approval_id == approval_id)
                .where(approval_requests.c.action_digest == action_digest)
                .where(approval_requests.c.status == ApprovalStatus.PENDING.value)
                .where(approval_requests.c.expires_at > current.isoformat())
                .values(
                    status=decision.value,
                    decided_at=current.isoformat(),
                    reviewer_id=reviewer_id,
                    reason=reason,
                )
            )
            if result.rowcount != 1:
                row = connection.execute(
                    select(approval_requests).where(
                        approval_requests.c.approval_id == approval_id
                    )
                ).mappings().one_or_none()
                if row is None:
                    raise ApprovalError("approval request not found")
                record = _record(row)
                if record.action_digest != action_digest:
                    raise ApprovalError("approval does not match this action")
                if current >= datetime.fromisoformat(record.expires_at):
                    connection.execute(
                        update(approval_requests)
                        .where(approval_requests.c.approval_id == approval_id)
                        .where(approval_requests.c.status == ApprovalStatus.PENDING.value)
                        .values(status=ApprovalStatus.EXPIRED.value)
                    )
                    raise ApprovalError("approval request has expired")
                raise ApprovalError("approval request has already been decided")
            row = connection.execute(
                select(approval_requests).where(approval_requests.c.approval_id == approval_id)
            ).mappings().one()
            return _record(row)

    def close(self) -> None:
        self.engine.dispose()


def _utc(value: datetime | None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return current.astimezone(UTC)


def _record(row: RowMapping) -> ApprovalRequest:
    return ApprovalRequest(
        approval_id=row["approval_id"],
        action_digest=row["action_digest"],
        agent_id=row["agent_id"],
        principal_id=row["principal_id"],
        tool=row["tool"],
        operation=row["operation"],
        resource=row["resource"],
        status=ApprovalStatus(row["status"]),
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        decided_at=row["decided_at"],
        reviewer_id=row["reviewer_id"],
        reason=row["reason"],
    )


def _values(record: ApprovalRequest) -> dict[str, str | None]:
    return {
        "approval_id": record.approval_id,
        "action_digest": record.action_digest,
        "agent_id": record.agent_id,
        "principal_id": record.principal_id,
        "tool": record.tool,
        "operation": record.operation,
        "resource": record.resource,
        "status": record.status.value,
        "created_at": record.created_at,
        "expires_at": record.expires_at,
        "decided_at": record.decided_at,
        "reviewer_id": record.reviewer_id,
        "reason": record.reason,
    }


def _replace_status(record: ApprovalRequest, status: ApprovalStatus) -> ApprovalRequest:
    return ApprovalRequest(
        record.approval_id,
        record.action_digest,
        record.agent_id,
        record.principal_id,
        record.tool,
        record.operation,
        record.resource,
        status,
        record.created_at,
        record.expires_at,
        record.decided_at,
        record.reviewer_id,
        record.reason,
    )
