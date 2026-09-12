"""Small ordered schema migration runner for ExecuSeal-owned tables."""

from sqlalchemy import Column, MetaData, String, Table, create_engine, inspect, select
from sqlalchemy.engine import Connection

from execuseal.approvals import metadata as approval_metadata
from execuseal.audit_store import metadata as audit_metadata
from execuseal.identities import metadata as identity_metadata
from execuseal.rate_limit import metadata as rate_limit_metadata
from execuseal.tokens import metadata as token_metadata

INITIAL_SCHEMA_VERSION = "0001_initial"
LATEST_SCHEMA_VERSION = "0002_distributed_rate_limits"
metadata = MetaData()
schema_migrations = Table(
    "schema_migrations",
    metadata,
    Column("version", String(64), primary_key=True),
)


def upgrade(database_url: str) -> tuple[str, ...]:
    """Apply every missing migration in order and return applied versions."""
    engine = create_engine(database_url, pool_pre_ping=True)
    applied: list[str] = []
    with engine.begin() as connection:
        metadata.create_all(connection)
        versions = set(connection.execute(select(schema_migrations.c.version)).scalars())
        if INITIAL_SCHEMA_VERSION not in versions:
            _initial_schema(connection)
            connection.execute(
                schema_migrations.insert().values(version=INITIAL_SCHEMA_VERSION)
            )
            applied.append(INITIAL_SCHEMA_VERSION)
        if LATEST_SCHEMA_VERSION not in versions:
            rate_limit_metadata.create_all(connection)
            connection.execute(
                schema_migrations.insert().values(version=LATEST_SCHEMA_VERSION)
            )
            applied.append(LATEST_SCHEMA_VERSION)
    engine.dispose()
    return tuple(applied)


def require_current(database_url: str) -> None:
    engine = create_engine(database_url, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            version = connection.execute(
                select(schema_migrations.c.version).where(
                    schema_migrations.c.version == LATEST_SCHEMA_VERSION
                )
            ).scalar_one_or_none()
        table_names = set(inspect(engine).get_table_names())
    except Exception as error:
        message = "Database schema is not initialized; run `execuseal db upgrade`"
        raise RuntimeError(message) from error
    finally:
        engine.dispose()
    if version is None:
        raise RuntimeError("Database schema is outdated; run `execuseal db upgrade`")
    required_tables = {
        "schema_migrations",
        "audit_events",
        "approval_requests",
        "consumed_tokens",
        "service_identities",
        "rate_limit_windows",
    }
    if not required_tables <= table_names:
        raise RuntimeError("Database schema is incomplete; run `execuseal db upgrade`")


def _initial_schema(connection: Connection) -> None:
    for owned_metadata in (
        audit_metadata,
        approval_metadata,
        token_metadata,
        identity_metadata,
    ):
        owned_metadata.create_all(connection)
