"""TraceCtrl Hermes Agent plugin — entry point.

Mirrors openclaw-tracectrl src/index.ts.  Loads config, initialises telemetry,
registers hook handlers, and starts the cleanup timer.

The actual hook handlers live in hooks.py (mirrors src/hooks.ts).
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from opentelemetry.trace import StatusCode

from config import TraceCtrlHermesConfig, load_config, apply_config_to_sdk
from telemetry import (
    TelemetryRuntime,
    init_telemetry,
    get_runtime,
)

logger = logging.getLogger("tracectrl.hermes")

_STATE_LOCK = threading.Lock()
_TRACE_STATES: dict[str, TurnState] = {}

_STALE_TTL_SECONDS = 300
_CLEANUP_INTERVAL_SECONDS = 60

_CONFIG: TraceCtrlHermesConfig | None = None
_TELEMETRY: TelemetryRuntime | None = None
_CLEANUP_TIMER: threading.Timer | None = None


def get_config() -> TraceCtrlHermesConfig | None:
    return _CONFIG


@dataclass
class TurnState:
    root_span: Any
    root_ctx: Any
    agent_spans: dict[int, Any] = field(default_factory=dict)
    tool_spans: dict[str, Any] = field(default_factory=dict)
    model_usage_spans: dict[int, Any] = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)
    model: str = ""
    provider: str = ""


def _state_key(session_id: str) -> str:
    return f"{session_id}:{threading.get_ident()}"


def get_state(session_id: str) -> TurnState | None:
    with _STATE_LOCK:
        return _TRACE_STATES.get(_state_key(session_id))


def set_state(session_id: str, state: TurnState) -> None:
    with _STATE_LOCK:
        _TRACE_STATES[_state_key(session_id)] = state


def del_state(session_id: str) -> None:
    with _STATE_LOCK:
        _TRACE_STATES.pop(_state_key(session_id), None)


def safe_end_span(span: Any) -> None:
    if span is not None:
        try:
            span.end()
        except Exception:
            pass


def close_state(session_id: str, status: StatusCode = StatusCode.OK, message: str = "") -> None:
    with _STATE_LOCK:
        state = _TRACE_STATES.pop(_state_key(session_id), None)
    if state is None:
        return
    if status != StatusCode.OK and message:
        state.root_span.set_status(status, message)
    else:
        state.root_span.set_status(status)
    for span in state.tool_spans.values():
        safe_end_span(span)
    for span in state.model_usage_spans.values():
        safe_end_span(span)
    for span in state.agent_spans.values():
        safe_end_span(span)
    safe_end_span(state.root_span)


def _start_cleanup_timer() -> None:
    global _CLEANUP_TIMER

    def _cleanup():
        now = time.time()
        with _STATE_LOCK:
            stale_keys = [
                key for key, state in _TRACE_STATES.items()
                if now - state.start_time > _STALE_TTL_SECONDS
            ]
            for key in stale_keys:
                state = _TRACE_STATES.pop(key, None)
                if state:
                    safe_end_span(state.root_span)
        _start_cleanup_timer()

    _CLEANUP_TIMER = threading.Timer(_CLEANUP_INTERVAL_SECONDS, _cleanup)
    _CLEANUP_TIMER.daemon = True
    _CLEANUP_TIMER.start()


def register(ctx: Any) -> None:
    """Hermes plugin registration — called by PluginManager during discovery."""
    global _CONFIG, _TELEMETRY

    _CONFIG = load_config()
    apply_config_to_sdk(_CONFIG)

    _TELEMETRY = init_telemetry(_CONFIG)
    if _TELEMETRY is None:
        logger.warning(
            "tracectrl: telemetry init failed — plugin will be inert. "
            "Check TRACECTRL_ENDPOINT and collector availability."
        )
        return

    from hooks import (
        on_session_start,
        pre_llm_call,
        pre_api_request,
        post_api_request,
        pre_tool_call,
        post_tool_call,
        post_llm_call,
        on_session_end,
        on_session_finalize,
        on_gateway_error,
        pre_approval_request,
        post_approval_response,
    )

    ctx.register_hook("on_session_start", on_session_start)
    ctx.register_hook("pre_llm_call", pre_llm_call)
    ctx.register_hook("pre_api_request", pre_api_request)
    ctx.register_hook("post_api_request", post_api_request)
    ctx.register_hook("pre_tool_call", pre_tool_call)
    ctx.register_hook("post_tool_call", post_tool_call)
    ctx.register_hook("post_llm_call", post_llm_call)
    ctx.register_hook("on_session_end", on_session_end)
    ctx.register_hook("on_session_finalize", on_session_finalize)
    ctx.register_hook("on_gateway_error", on_gateway_error)
    ctx.register_hook("pre_approval_request", pre_approval_request)
    ctx.register_hook("post_approval_response", post_approval_response)

    _start_cleanup_timer()

    logger.info(
        "tracectrl: hermes plugin registered — endpoint=%s service=%s",
        _CONFIG.endpoint, _CONFIG.service_name,
    )
