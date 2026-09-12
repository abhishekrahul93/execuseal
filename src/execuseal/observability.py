"""Low-cardinality Prometheus metrics for production operations."""

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest


class GatewayMetrics:
    """Application-owned registry avoids global state and duplicate test collectors."""

    content_type = "text/plain; version=0.0.4; charset=utf-8"

    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.requests = Counter(
            "execuseal_http_requests_total",
            "Gateway HTTP requests.",
            ("method", "route", "status"),
            registry=self.registry,
        )
        self.duration = Histogram(
            "execuseal_http_request_duration_seconds",
            "Gateway HTTP request duration.",
            ("method", "route"),
            registry=self.registry,
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
        )
        self.auth_failures = Counter(
            "execuseal_auth_failures_total",
            "Rejected authentication attempts.",
            ("credential_type",),
            registry=self.registry,
        )
        self.rate_limited = Counter(
            "execuseal_rate_limited_total",
            "Requests rejected by the distributed rate limiter.",
            ("identity_type",),
            registry=self.registry,
        )
        self.decisions = Counter(
            "execuseal_safety_decisions_total",
            "Safety decisions returned by the gateway.",
            ("decision_type", "action"),
            registry=self.registry,
        )
        self.ready = Gauge(
            "execuseal_ready",
            "Whether all gateway readiness checks passed.",
            registry=self.registry,
        )

    def render(self) -> bytes:
        return generate_latest(self.registry)
