import pytest

from execuseal.rate_limit import SqlRateLimiter


def test_window_resets_after_interval(tmp_path) -> None:
    limiter = SqlRateLimiter(f"sqlite:///{tmp_path / 'limits.db'}", 1, 10)
    limiter.initialize()

    assert limiter.allow("key", now=0) == (True, 0, 10)
    assert limiter.allow("key", now=5) == (False, 0, 5)
    assert limiter.allow("key", now=10) == (True, 0, 10)
    limiter.close()


def test_limit_is_shared_across_instances(tmp_path) -> None:
    url = f"sqlite:///{tmp_path / 'shared.db'}"
    first = SqlRateLimiter(url, 2, 60)
    second = SqlRateLimiter(url, 2, 60)
    first.initialize()

    assert first.allow("identity", now=1)[:2] == (True, 1)
    assert second.allow("identity", now=2)[:2] == (True, 0)
    assert first.allow("identity", now=3)[:2] == (False, 0)
    first.close()
    second.close()


@pytest.mark.parametrize(("requests", "seconds"), [(0, 1), (1, 0)])
def test_requires_positive_configuration(requests: int, seconds: int) -> None:
    with pytest.raises(ValueError, match="positive"):
        SqlRateLimiter("sqlite://", requests, seconds)
