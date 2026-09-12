"""Privacy-aware, hash-chained audit evidence for authorization decisions."""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from execuseal.actions import ActionContext, ToolAction
from execuseal.firewall import ActionDecision


@dataclass(frozen=True, slots=True)
class AuditRecord:
    event_id: str
    occurred_at: str
    agent_id: str
    principal_id: str
    environment: str
    tool: str
    operation: str
    resource: str
    decision: str
    policy_rule_id: str | None
    blast_radius_score: int
    previous_hash: str
    record_hash: str


class AuditChain:
    """Create verifiable records without storing prompts or tool parameters."""

    def __init__(self, records: tuple[AuditRecord, ...] = ()) -> None:
        self._records: list[AuditRecord] = list(records)
        if not self.verify():
            raise ValueError("initial audit records do not form a valid hash chain")

    @property
    def records(self) -> tuple[AuditRecord, ...]:
        return tuple(self._records)

    def append(
        self,
        event_id: str,
        action: ToolAction,
        context: ActionContext,
        decision: ActionDecision,
        occurred_at: datetime | None = None,
    ) -> AuditRecord:
        timestamp = (occurred_at or datetime.now(UTC)).astimezone(UTC).isoformat()
        previous_hash = self._records[-1].record_hash if self._records else "GENESIS"
        payload: dict[str, str | int | None] = {
            "event_id": event_id,
            "occurred_at": timestamp,
            "agent_id": context.agent_id,
            "principal_id": context.principal_id,
            "environment": context.environment.value,
            "tool": action.tool,
            "operation": action.operation,
            "resource": action.resource,
            "decision": decision.action.value,
            "policy_rule_id": decision.policy_rule_id,
            "blast_radius_score": decision.blast_radius.score,
            "previous_hash": previous_hash,
        }
        digest = _digest(payload)
        record = AuditRecord(**payload, record_hash=digest)  # type: ignore[arg-type]
        self._records.append(record)
        return record

    def verify(self) -> bool:
        expected_previous = "GENESIS"
        for record in self._records:
            payload = asdict(record)
            record_hash = str(payload.pop("record_hash"))
            if payload["previous_hash"] != expected_previous or _digest(payload) != record_hash:
                return False
            expected_previous = record_hash
        return True


def _digest(payload: Mapping[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()
