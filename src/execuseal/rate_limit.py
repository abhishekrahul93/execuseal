"""Atomic SQL-backed fixed-window rate limiting for gateway replicas."""

import hashlib
import time
from typing import Any

from sqlalchemy import BigInteger, Column, Integer, MetaData, String, Table, case, create_engine
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

metadata = MetaData()
rate_limit_windows = Table(
    "rate_limit_windows",
    metadata,
    Column("identity_hash", String(64), primary_key=True),
    Column("window_start", BigInteger, nullable=False),
    Column("request_count", Integer, nullable=False),
)


class SqlRateLimiter:
    """Share per-identity limits across processes through one atomic upsert."""

    def __init__(self, database_url: str, requests: int, window_seconds: int) -> None:
        if requests < 1 or window_seconds < 1:
            raise ValueError("rate limit and window must be positive")
        self.requests = requests
        self.window_seconds = window_seconds
        self._engine = create_engine(database_url, pool_pre_ping=True)

    def initialize(self) -> None:
        metadata.create_all(self._engine)

    def allow(self, identity: str, now: float | None = None) -> tuple[bool, int, int]:
        """Return allowed, remaining requests, and seconds until reset."""
        current = time.time() if now is None else now
        window_start = int(current // self.window_seconds) * self.window_seconds
        reset_after = max(1, window_start + self.window_seconds - int(current))
        identity_hash = hashlib.sha256(identity.encode()).hexdigest()

        dialect = self._engine.dialect.name
        if dialect == "postgresql":
            insert: Any = postgresql_insert(rate_limit_windows)
        elif dialect == "sqlite":
            insert = sqlite_insert(rate_limit_windows)
        else:  # pragma: no cover - supported deployment dialects are explicit
            raise RuntimeError(f"Unsupported rate-limit database dialect: {dialect}")

        statement = insert.values(
            identity_hash=identity_hash,
            window_start=window_start,
            request_count=1,
        )
        statement = statement.on_conflict_do_update(
            index_elements=[rate_limit_windows.c.identity_hash],
            set_={
                "window_start": window_start,
                "request_count": case(
                    (
                        rate_limit_windows.c.window_start == window_start,
                        rate_limit_windows.c.request_count + 1,
                    ),
                    else_=1,
                ),
            },
        ).returning(rate_limit_windows.c.request_count)

        with self._engine.begin() as connection:
            count = connection.execute(statement).scalar_one()

        return count <= self.requests, max(0, self.requests - count), reset_after

    def ping(self) -> bool:
        try:
            with self._engine.connect() as connection:
                connection.execute(rate_limit_windows.select().limit(1))
            return True
        except Exception:
            return False

    def close(self) -> None:
        self._engine.dispose()
