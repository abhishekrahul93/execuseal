"""Durable SQL audit storage with serialized PostgreSQL hash-chain writes."""

from datetime import datetime

from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine, select, text
from sqlalchemy.engine import Connection, Engine

from agent_safety_lab.actions import ActionContext, ToolAction
from agent_safety_lab.audit import AuditChain, AuditRecord
from agent_safety_lab.firewall import ActionDecision

metadata = MetaData()
audit_events = Table(
    "audit_events",
    metadata,
    Column("sequence", Integer, primary_key=True, autoincrement=True),
    Column("event_id", String(128), nullable=False, unique=True),
    Column("occurred_at", String(64), nullable=False),
    Column("agent_id", String(128), nullable=False),
    Column("principal_id", String(128), nullable=False),
    Column("environment", String(32), nullable=False),
    Column("tool", String(128), nullable=False),
    Column("operation", String(128), nullable=False),
    Column("resource", String(512), nullable=False),
    Column("decision", String(16), nullable=False),
    Column("policy_rule_id", String(128), nullable=True),
    Column("blast_radius_score", Integer, nullable=False),
    Column("previous_hash", String(64), nullable=False),
    Column("record_hash", String(64), nullable=False, unique=True),
)


class SqlAuditStore:
    """Persist a global audit chain without retaining prompts or parameters."""

    def __init__(self, database_url: str) -> None:
        self.engine: Engine = create_engine(database_url, pool_pre_ping=True)

    def initialize(self) -> None:
        metadata.create_all(self.engine)

    def append(
        self,
        event_id: str,
        action: ToolAction,
        context: ActionContext,
        decision: ActionDecision,
        occurred_at: datetime | None = None,
    ) -> AuditRecord:
        with self.engine.begin() as connection:
            if connection.dialect.name == "postgresql":
                connection.execute(text("SELECT pg_advisory_xact_lock(742091551)"))
            chain = AuditChain(self._records(connection))
            record = chain.append(event_id, action, context, decision, occurred_at)
            connection.execute(audit_events.insert().values(**_record_values(record)))
            return record

    def verify(self) -> bool:
        with self.engine.connect() as connection:
            try:
                return AuditChain(self._records(connection)).verify()
            except ValueError:
                return False

    def count(self) -> int:
        with self.engine.connect() as connection:
            return len(self._records(connection))

    def close(self) -> None:
        self.engine.dispose()

    @staticmethod
    def _records(connection: Connection) -> tuple[AuditRecord, ...]:
        rows = connection.execute(select(audit_events).order_by(audit_events.c.sequence)).mappings()
        return tuple(
            AuditRecord(
                event_id=row["event_id"],
                occurred_at=row["occurred_at"],
                agent_id=row["agent_id"],
                principal_id=row["principal_id"],
                environment=row["environment"],
                tool=row["tool"],
                operation=row["operation"],
                resource=row["resource"],
                decision=row["decision"],
                policy_rule_id=row["policy_rule_id"],
                blast_radius_score=row["blast_radius_score"],
                previous_hash=row["previous_hash"],
                record_hash=row["record_hash"],
            )
            for row in rows
        )


def _record_values(record: AuditRecord) -> dict[str, str | int | None]:
    return {
        "event_id": record.event_id,
        "occurred_at": record.occurred_at,
        "agent_id": record.agent_id,
        "principal_id": record.principal_id,
        "environment": record.environment,
        "tool": record.tool,
        "operation": record.operation,
        "resource": record.resource,
        "decision": record.decision,
        "policy_rule_id": record.policy_rule_id,
        "blast_radius_score": record.blast_radius_score,
        "previous_hash": record.previous_hash,
        "record_hash": record.record_hash,
    }
