import os
import shutil
import threading
from typing import Optional, Tuple

import prometheus_client
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

# Global lock for thread-safe registry access
_lock = threading.Lock()

# Standard low-cardinality latency buckets
LATENCY_BUCKETS = (
    0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 10.0, float("inf")
)

# Registry reference
_registry: CollectorRegistry = prometheus_client.REGISTRY
_is_multiprocess = bool(os.environ.get("PROMETHEUS_MULTIPROC_DIR"))


def _get_or_create(cls, name: str, documentation: str, labelnames=(), **kwargs):
    """Retrieve existing collector if registered, or create a new one safely."""
    with _lock:
        for collector in _registry._collectors:
            names = getattr(collector, "_names", [getattr(collector, "_name", "")])
            if name in names:
                return collector
        try:
            return cls(name, documentation, labelnames=labelnames, registry=_registry, **kwargs)
        except ValueError:
            # Handle concurrent registration
            for collector in _registry._collectors:
                names = getattr(collector, "_names", [getattr(collector, "_name", "")])
                if name in names:
                    return collector
            raise


# Core Metrics (strictly bounded, low cardinality)
http_requests_total = _get_or_create(
    Counter,
    "http_requests_total",
    "Total HTTP requests received",
    labelnames=["method", "path", "status"],
)

http_request_duration_seconds = _get_or_create(
    Histogram,
    "http_request_duration_seconds",
    "HTTP request latency in seconds",
    labelnames=["method", "path"],
    buckets=LATENCY_BUCKETS,
)

dependency_healthy = _get_or_create(
    Gauge,
    "dependency_healthy",
    "Health status of backend dependencies (1=healthy, 0=unhealthy)",
    labelnames=["dependency"],
)

rate_limit_rejections_total = _get_or_create(
    Counter,
    "rate_limit_rejections_total",
    "Total requests rejected by rate limiting policies",
    labelnames=["policy"],
)

evidence_scans_total = _get_or_create(
    Counter,
    "evidence_scans_total",
    "Total evidence attachment antivirus scans by outcome",
    labelnames=["result"],
)

reconciliation_runs_total = _get_or_create(
    Counter,
    "reconciliation_runs_total",
    "Total background evidence reconciliation executions by status",
    labelnames=["status"],
)

moderator_actions_total = _get_or_create(
    Counter,
    "moderator_actions_total",
    "Total moderator state mutations by action type",
    labelnames=["action"],
)


def is_pid_alive(pid: int) -> bool:
    """Check if a process with given PID is currently running."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError as err:
        import errno
        return err.errno == errno.EPERM


def cleanup_stale_multiprocess_files(multiproc_dir: str) -> None:
    """Remove multiprocess metric files belonging only to terminated (stale) processes.

    Never deletes files belonging to active live workers.
    """
    if not os.path.isdir(multiproc_dir):
        return

    import re
    pid_pattern = re.compile(r"_(\d+)\.db$")
    current_pid = os.getpid()

    for fname in os.listdir(multiproc_dir):
        file_path = os.path.join(multiproc_dir, fname)
        if not os.path.isfile(file_path):
            continue

        match = pid_pattern.search(fname)
        if match:
            file_pid = int(match.group(1))
            if file_pid == current_pid:
                continue
            if is_pid_alive(file_pid):
                # Worker is currently alive - DO NOT DELETE
                continue

        # File is from a dead PID or stale non-PID artifact
        try:
            os.unlink(file_path)
        except OSError:
            pass


def setup_multiprocess_dir(cleanup_stale: bool = True) -> Optional[str]:
    """Ensure multiprocess directory exists and safely clear only stale dead-worker files."""
    multiproc_dir = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
    if not multiproc_dir:
        return None

    path = os.path.abspath(multiproc_dir)
    os.makedirs(path, exist_ok=True)
    if cleanup_stale:
        cleanup_stale_multiprocess_files(path)
    return path


def generate_metrics_response() -> Tuple[bytes, str]:
    """Generate serialized OpenMetrics / Prometheus scrape payload."""
    multiproc_dir = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
    if multiproc_dir and os.path.isdir(multiproc_dir):
        from prometheus_client import multiprocess

        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        data = generate_latest(registry)
    else:
        data = generate_latest(_registry)

    return data, CONTENT_TYPE_LATEST
