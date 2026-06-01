"""OpenTelemetry provider initialisation using the tracectrl SDK.

Supports both HTTP and gRPC OTLP export (controlled by TRACECTRL_PROTOCOL).
Creates a TracerProvider, MeterProvider, and pre-allocates all counters /
histograms with the same names as the openclaw-tracectrl plugin.

Mirrors openclaw-tracectrl src/telemetry.ts.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from opentelemetry import trace, metrics
from opentelemetry.sdk.resources import Resource

logger = logging.getLogger("tracectrl.hermes")

_INIT_LOCK = threading.Lock()
_initialized = False
_INIT_FAILED = False

_runtime: TelemetryRuntime | None = None


@dataclass
class TelemetryCounters:
    messages_received: Any = None
    messages_sent: Any = None
    tool_calls: Any = None
    tool_errors: Any = None
    tokens_total: Any = None
    tokens_prompt: Any = None
    tokens_completion: Any = None
    security_events: Any = None
    session_resets: Any = None


@dataclass
class TelemetryHistograms:
    agent_turn_duration: Any = None
    tool_duration: Any = None


@dataclass
class TelemetryRuntime:
    tracer: Any = None
    meter: Any = None
    counters: TelemetryCounters = field(default_factory=TelemetryCounters)
    histograms: TelemetryHistograms = field(default_factory=TelemetryHistograms)
    tracer_provider: Any = None
    meter_provider: Any = None

    def shutdown(self) -> None:
        for provider in (self.tracer_provider, self.meter_provider):
            if provider is not None:
                try:
                    provider.shutdown()
                except Exception:
                    pass


def is_failed() -> bool:
    return _INIT_FAILED


def get_runtime() -> TelemetryRuntime | None:
    return _runtime


def init_telemetry(config: Any) -> TelemetryRuntime | None:
    """Initialise OTel telemetry. Returns None on error if fail_silently."""
    global _runtime, _initialized, _INIT_FAILED

    if _initialized:
        return _runtime
    if _INIT_FAILED:
        return None

    with _INIT_LOCK:
        if _initialized:
            return _runtime
        if _INIT_FAILED:
            return None

        try:
            return _do_init(config)
        except Exception as exc:
            _INIT_FAILED = True
            if not config.fail_silently:
                raise
            logger.warning("tracectrl: telemetry init failed: %s", exc)
            return None


def _build_exporters(config: Any):
    """Build trace and metric exporters based on protocol config.

    Returns (trace_exporter, metric_exporter) or (None, None) on failure.
    """
    if config.protocol == "grpc":
        return _build_grpc_exporters(config)
    return _build_http_exporters(config)


def _build_grpc_exporters(config: Any):
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter

    parsed = urlparse(config.endpoint)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 4317)
    insecure = parsed.scheme != "https"

    headers = dict(config.headers) if config.headers else {}
    if config.api_key:
        headers["Authorization"] = f"Bearer {config.api_key}"

    endpoint_str = f"{host}:{port}"

    trace_exporter = OTLPSpanExporter(
        endpoint=endpoint_str, headers=headers, insecure=insecure,
    )
    metric_exporter = OTLPMetricExporter(
        endpoint=endpoint_str, headers=headers, insecure=insecure,
    )
    return trace_exporter, metric_exporter


def _build_http_exporters(config: Any):
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter

    base = config.endpoint.rstrip("/")
    headers = dict(config.headers) if config.headers else {}
    if config.api_key:
        headers["Authorization"] = f"Bearer {config.api_key}"

    trace_exporter = OTLPSpanExporter(
        endpoint=f"{base}/v1/traces", headers=headers,
    )
    metric_exporter = OTLPMetricExporter(
        endpoint=f"{base}/v1/metrics", headers=headers,
    )
    return trace_exporter, metric_exporter


def _do_init(config: Any) -> TelemetryRuntime:
    global _runtime, _initialized

    resource = Resource.create({
        "service.name": config.service_name,
        "tracectrl.plugin.version": "0.1.0",
    })

    # --- TracerProvider ---
    tracer_provider = None
    tracer = trace.get_tracer("tracectrl-hermes", "0.1.0")

    if config.traces:
        try:
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            trace_exporter, _ = _build_exporters(config)

            tracer_provider = TracerProvider(resource=resource)
            tracer_provider.add_span_processor(BatchSpanProcessor(trace_exporter))

            try:
                from tracectrl.processor import TraceCtrlSpanProcessor
                tracer_provider.add_span_processor(TraceCtrlSpanProcessor())
            except Exception:
                pass

            trace.set_tracer_provider(tracer_provider)
            tracer = tracer_provider.get_tracer("tracectrl-hermes", "0.1.0")
            logger.info("tracectrl: trace provider registered (protocol=%s)", config.protocol)
        except Exception:
            logger.info("tracectrl: trace provider unavailable, using default")

    # --- MeterProvider ---
    meter_provider = None
    meter = metrics.get_meter("tracectrl-hermes", "0.1.0")

    if config.metrics:
        try:
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader

            _, metric_exporter = _build_exporters(config)

            metric_reader = PeriodicExportingMetricReader(
                exporter=metric_exporter,
                export_interval_millis=config.metrics_interval_ms,
            )
            meter_provider = MeterProvider(resource=resource, readers=[metric_reader])
            metrics.set_global_meter_provider(meter_provider)
            meter = meter_provider.get_meter("tracectrl-hermes", "0.1.0")
            logger.info("tracectrl: metric provider registered (protocol=%s)", config.protocol)
        except Exception:
            logger.info("tracectrl: metric provider unavailable, using default")

    # --- Counters (same names as openclaw-tracectrl) ---
    counters = TelemetryCounters(
        messages_received=meter.create_counter(
            "tracectrl.messages.received",
            description="Number of inbound messages received",
        ),
        messages_sent=meter.create_counter(
            "tracectrl.messages.sent",
            description="Number of outbound messages sent",
        ),
        tool_calls=meter.create_counter(
            "tracectrl.tool.calls",
            description="Number of tool invocations",
        ),
        tool_errors=meter.create_counter(
            "tracectrl.tool.errors",
            description="Number of tool invocations that returned errors",
        ),
        tokens_total=meter.create_counter(
            "tracectrl.tokens.total",
            description="Total tokens consumed",
        ),
        tokens_prompt=meter.create_counter(
            "tracectrl.tokens.prompt",
            description="Prompt (input) tokens consumed",
        ),
        tokens_completion=meter.create_counter(
            "tracectrl.tokens.completion",
            description="Completion (output) tokens consumed",
        ),
        security_events=meter.create_counter(
            "tracectrl.security.events",
            description="Security-relevant events detected",
        ),
        session_resets=meter.create_counter(
            "tracectrl.session.resets",
            description="Session reset events",
        ),
    )

    # --- Histograms (same names as openclaw-tracectrl) ---
    histograms = TelemetryHistograms(
        agent_turn_duration=meter.create_histogram(
            "tracectrl.agent.turn.duration_ms",
            description="Duration of an agent turn in milliseconds",
            unit="ms",
        ),
        tool_duration=meter.create_histogram(
            "tracectrl.tool.duration_ms",
            description="Duration of a tool call in milliseconds",
            unit="ms",
        ),
    )

    # --- Startup span (parity with openclaw-tracectrl gateway:startup) ---
    try:
        startup_span = tracer.start_span(
            "tracectrl.gateway.startup",
            attributes={
                "tracectrl.plugin.version": "0.1.0",
                "tracectrl.agent.framework": "hermes",
                "tracectrl.diagnostic_events": "active",
                "tracectrl.protocol": config.protocol,
            },
        )
        startup_span.set_status(trace.StatusCode.OK)
        startup_span.end()
    except Exception:
        pass

    _runtime = TelemetryRuntime(
        tracer=tracer,
        meter=meter,
        counters=counters,
        histograms=histograms,
        tracer_provider=tracer_provider,
        meter_provider=meter_provider,
    )
    _initialized = True
    return _runtime
