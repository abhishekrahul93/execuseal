"""Contracts for proposed AI-agent actions and their execution context."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from types import MappingProxyType


class Environment(StrEnum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class DataClassification(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3


class Impact(IntEnum):
    NONE = 0
    SINGLE_RECORD = 1
    MULTIPLE_RECORDS = 2
    SYSTEM_WIDE = 3


@dataclass(frozen=True, slots=True)
class ActionContext:
    """Verified identity and environment supplied by the host application."""

    agent_id: str
    principal_id: str
    environment: Environment

    def __post_init__(self) -> None:
        if not self.agent_id.strip() or not self.principal_id.strip():
            raise ValueError("agent_id and principal_id must not be empty")


@dataclass(frozen=True, slots=True)
class ToolAction:
    """A side-effect proposal intercepted before a tool is invoked.

    Parameters are metadata-only and should never contain raw credentials,
    prompt text, or sensitive record values.
    """

    tool: str
    operation: str
    resource: str
    data_classification: DataClassification = DataClassification.INTERNAL
    impact: Impact = Impact.NONE
    external_destination: bool = False
    parameters: Mapping[str, str | int | bool] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.tool.strip() or not self.operation.strip() or not self.resource.strip():
            raise ValueError("tool, operation, and resource must not be empty")
        object.__setattr__(self, "parameters", MappingProxyType(dict(self.parameters)))
