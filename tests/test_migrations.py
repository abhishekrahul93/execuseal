from pathlib import Path

import pytest

from execuseal.migrations import (
    INITIAL_SCHEMA_VERSION,
    LATEST_SCHEMA_VERSION,
    require_current,
    upgrade,
)


def test_migration_is_versioned_and_idempotent(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'schema.db'}"

    assert upgrade(database_url) == (INITIAL_SCHEMA_VERSION, LATEST_SCHEMA_VERSION)
    assert upgrade(database_url) == ()
    require_current(database_url)


def test_current_schema_check_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="db upgrade"):
        require_current(f"sqlite:///{tmp_path / 'empty.db'}")
