from metrics.models import AgentMetrics

__all__ = ["MetricsCalculator", "AgentMetrics"]


def __getattr__(name: str):
    if name == "MetricsCalculator":
        from metrics.calculator import MetricsCalculator

        return MetricsCalculator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
