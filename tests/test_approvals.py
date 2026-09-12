from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from execuseal.approvals import ApprovalError, ApprovalStatus, SqlApprovalStore


def test_approval_is_persistent_and_can_only_be_decided_once(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'approvals.db'}"
    store = SqlApprovalStore(database_url, ttl_seconds=60)
    store.initialize()
    now = datetime(2026, 1, 1, tzinfo=UTC)
    created = store.create(
        "approval-1",
        "a" * 64,
        "agent-1",
        "principal-1",
        "database",
        "update",
        "inventory",
        now,
    )

    assert created.status is ApprovalStatus.PENDING
    restarted = SqlApprovalStore(database_url, ttl_seconds=60)
    decided = restarted.decide(
        "approval-1",
        "a" * 64,
        "reviewer-fingerprint",
        ApprovalStatus.APPROVED,
        "Change ticket verified",
        now + timedelta(seconds=1),
    )
    assert decided.status is ApprovalStatus.APPROVED
    assert decided.reviewer_id == "reviewer-fingerprint"

    with pytest.raises(ApprovalError, match="already been decided"):
        restarted.decide(
            "approval-1",
            "a" * 64,
            "another-reviewer",
            ApprovalStatus.REJECTED,
            "No",
            now + timedelta(seconds=2),
        )


def test_approval_rejects_substitution_and_expiry(tmp_path: Path) -> None:
    store = SqlApprovalStore(f"sqlite:///{tmp_path / 'approvals.db'}", ttl_seconds=30)
    store.initialize()
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store.create("approval-1", "a" * 64, "a", "p", "t", "o", "r", now)

    with pytest.raises(ApprovalError, match="does not match"):
        store.decide(
            "approval-1",
            "b" * 64,
            "reviewer",
            ApprovalStatus.APPROVED,
            "Approve",
            now + timedelta(seconds=1),
        )
    with pytest.raises(ApprovalError, match="expired"):
        store.decide(
            "approval-1",
            "a" * 64,
            "reviewer",
            ApprovalStatus.APPROVED,
            "Approve",
            now + timedelta(seconds=30),
        )
    expired = store.get("approval-1", now + timedelta(seconds=31))
    assert expired is not None
    assert expired.status is ApprovalStatus.EXPIRED


@pytest.mark.parametrize("ttl", [29, 86_401])
def test_approval_ttl_is_bounded(ttl: int) -> None:
    with pytest.raises(ValueError, match="TTL"):
        SqlApprovalStore("sqlite://", ttl_seconds=ttl)
