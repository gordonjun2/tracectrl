"""Configuration for the TraceCtrl Hermes plugin.

Reads from environment variables (TRACECTRL_*) matching the tracectrl SDK
convention, with sensible defaults for Hermes Agent.

Mirrors openclaw-tracectrl src/config.ts.
"""

import os
from dataclasses import dataclass, field

_DEFAULT_ENDPOINT_HTTP = "http://localhost:4318"
_DEFAULT_ENDPOINT_GRPC = "http://localhost:4317"
_DEFAULT_SERVICE_NAME = "hermes-agent"
_DEFAULT_METRICS_INTERVAL_MS = 30_000


@dataclass
class TraceCtrlHermesConfig:
    endpoint: str = _DEFAULT_ENDPOINT_HTTP
    service_name: str = _DEFAULT_SERVICE_NAME
    api_key: str | None = None
    capture_content: bool = False
    protocol: str = "http"
    traces: bool = True
    metrics: bool = True
    metrics_interval_ms: int = _DEFAULT_METRICS_INTERVAL_MS
    headers: dict[str, str] = field(default_factory=dict)
    fail_silently: bool = True


def load_config() -> TraceCtrlHermesConfig:
    """Build config from environment variables."""
    protocol = os.getenv("TRACECTRL_PROTOCOL", "http").lower()
    if protocol not in ("http", "grpc"):
        protocol = "http"

    default_endpoint = _DEFAULT_ENDPOINT_HTTP if protocol == "http" else _DEFAULT_ENDPOINT_GRPC

    headers: dict[str, str] = {}
    raw_headers = os.getenv("TRACECTRL_HEADERS", "")
    if raw_headers:
        for pair in raw_headers.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                headers[k.strip()] = v.strip()

    return TraceCtrlHermesConfig(
        endpoint=os.getenv("TRACECTRL_ENDPOINT", default_endpoint),
        service_name=os.getenv("TRACECTRL_SERVICE_NAME", _DEFAULT_SERVICE_NAME),
        api_key=os.getenv("TRACECTRL_API_KEY") or None,
        capture_content=os.getenv("TRACECTRL_CAPTURE_CONTENT", "").lower() in ("true", "1", "yes"),
        protocol=protocol,
        traces=os.getenv("TRACECTRL_TRACES", "true").lower() in ("true", "1", "yes"),
        metrics=os.getenv("TRACECTRL_METRICS", "true").lower() in ("true", "1", "yes"),
        metrics_interval_ms=int(os.getenv("TRACECTRL_METRICS_INTERVAL_MS", str(_DEFAULT_METRICS_INTERVAL_MS))),
        headers=headers,
        fail_silently=os.getenv("TRACECTRL_FAIL_SILENTLY", "true").lower() in ("true", "1", "yes"),
    )


def apply_config_to_sdk(config: TraceCtrlHermesConfig) -> None:
    """Push config into the tracectrl SDK's global state."""
    try:
        from tracectrl.config import configure
        configure(
            endpoint=config.endpoint,
            service_name=config.service_name,
            api_key=config.api_key,
            fail_silently=config.fail_silently,
        )
    except Exception:
        pass
