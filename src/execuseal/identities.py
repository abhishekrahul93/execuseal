"""SQL-backed scoped service identities with rotation and revocation."""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import Boolean, Column, MetaData, String, Table, create_engine, select, update
from sqlalchemy.engine import Engine

metadata = MetaData()
service_identities = Table(
    "service_identities",
    metadata,
    Column("key_hash", String(64), primary_key=True),
    Column("key_id", String(64), nullable=False, unique=True),
    Column("principal_id", String(128), nullable=False),
    Column("scopes", String(512), nullable=False),
    Column("created_at", String(64), nullable=False),
    Column("expires_at", String(64), nullable=True),
    Column("revoked", Boolean, nullable=False, default=False),
)


@dataclass(frozen=True, slots=True)
class ServiceIdentity:
    key_id: str
    principal_id: str
    scopes: frozenset[str]
    created_at: str
    expires_at: str | None
    revoked: bool


@dataclass(frozen=True, slots=True)
class IssuedIdentity:
    identity: ServiceIdentity
    api_key: str


class SqlIdentityStore:
    def __init__(self, database_url: str) -> None:
        self.engine: Engine = create_engine(database_url, pool_pre_ping=True)

    def initialize(self) -> None:
        metadata.create_all(self.engine)

    def bootstrap(self, api_key: str, principal_id: str, scopes: frozenset[str]) -> None:
        digest = _digest(api_key)
        key_id = f"bootstrap-{digest[:12]}"
        now = datetime.now(UTC).isoformat()
        with self.engine.begin() as connection:
            existing = connection.execute(
                select(service_identities.c.key_hash).where(
                    service_identities.c.key_hash == digest
                )
            ).first()
            if existing is None:
                connection.execute(
                    service_identities.insert().values(
                        key_hash=digest,
                        key_id=key_id,
                        principal_id=principal_id,
                        scopes=_scopes(scopes),
                        created_at=now,
                        expires_at=None,
                        revoked=False,
                    )
                )

    def issue(
        self,
        principal_id: str,
        scopes: frozenset[str],
        ttl_seconds: int | None = None,
    ) -> IssuedIdentity:
        if not scopes or not scopes <= {"scan", "authorize", "admin"}:
            raise ValueError("identity scopes are invalid")
        if ttl_seconds is not None and not 60 <= ttl_seconds <= 31_536_000:
            raise ValueError("identity TTL must be between 60 and 31536000 seconds")
        key_id = secrets.token_urlsafe(12)
        api_key = f"exk_{key_id}_{secrets.token_urlsafe(32)}"
        now = datetime.now(UTC)
        expires = now + timedelta(seconds=ttl_seconds) if ttl_seconds else None
        identity = ServiceIdentity(
            key_id,
            principal_id,
            scopes,
            now.isoformat(),
            expires.isoformat() if expires else None,
            False,
        )
        with self.engine.begin() as connection:
            connection.execute(
                service_identities.insert().values(
                    key_hash=_digest(api_key),
                    key_id=key_id,
                    principal_id=principal_id,
                    scopes=_scopes(scopes),
                    created_at=identity.created_at,
                    expires_at=identity.expires_at,
                    revoked=False,
                )
            )
        return IssuedIdentity(identity, api_key)

    def authenticate(self, api_key: str, required_scope: str) -> ServiceIdentity | None:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(service_identities).where(
                    service_identities.c.key_hash == _digest(api_key)
                )
            ).mappings().one_or_none()
        if row is None or row["revoked"]:
            return None
        if row["expires_at"] and datetime.now(UTC) >= datetime.fromisoformat(row["expires_at"]):
            return None
        scopes = frozenset(row["scopes"].split(","))
        if required_scope not in scopes:
            return None
        return ServiceIdentity(
            row["key_id"],
            row["principal_id"],
            scopes,
            row["created_at"],
            row["expires_at"],
            row["revoked"],
        )

    def revoke(self, key_id: str) -> bool:
        with self.engine.begin() as connection:
            result = connection.execute(
                update(service_identities)
                .where(service_identities.c.key_id == key_id)
                .where(service_identities.c.revoked.is_(False))
                .values(revoked=True)
            )
        return result.rowcount == 1

    def close(self) -> None:
        self.engine.dispose()


def _digest(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


def _scopes(scopes: frozenset[str]) -> str:
    return ",".join(sorted(scopes))
