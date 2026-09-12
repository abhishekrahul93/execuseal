import pytest

from agent_safety_lab.rate_limit import RateLimiter


def test_window_resets_after_interval() -> None:
    limiter = RateLimiter(1, 10)

    assert limiter.allow("key", now=0) == (True, 0)
    assert limiter.allow("key", now=5) == (False, 0)
    assert limiter.allow("key", now=10) == (True, 0)


@pytest.mark.parametrize(("requests", "seconds"), [(0, 1), (1, 0)])
def test_requires_positive_configuration(requests: int, seconds: int) -> None:
    with pytest.raises(ValueError, match="positive"):
        RateLimiter(requests, seconds)
